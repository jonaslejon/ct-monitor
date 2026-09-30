#!/usr/bin/env python3
"""Back-pressure when Elasticsearch refuses writes, and the bounded queues (2026-09-30).

Run: python3 -m unittest -v test_es_retry_cap
"""
import importlib.util
import queue
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import elasticsearch_output  # noqa: E402


class FakeResponse:
    def __init__(self, status_code, n_items=0, item_status=201):
        self.status_code = status_code
        self.text = '' if status_code == 200 else '{"error":"cluster_block_exception"}'
        self._items = [{'create': {'status': item_status}} for _ in range(n_items)]

    def json(self):
        return {'errors': False, 'items': self._items}


class FakeSession:
    """Answers every _bulk with `status` (429 = the read-only block) until told otherwise."""

    def __init__(self, status=429):
        self.status = status
        self.posts = 0

    def post(self, url, data, timeout):
        self.posts += 1
        n = data.count('\n') // 2
        return FakeResponse(self.status, n_items=n if self.status == 200 else 0)

    def close(self):
        pass


def make_es(batch_size=10, retry_max_docs=30, status=429):
    with patch('elasticsearch_output.requests.Session', return_value=MagicMock()):
        es = elasticsearch_output.ElasticsearchOutput(es_host='http://es.invalid:9200', batch_size=batch_size)
    es.retry_max_docs = retry_max_docs
    es.session = FakeSession(status)
    es._sleep = lambda secs: None
    return es


def doc(i):
    return {'name': f'host{i}.example', 'ts': 1, 'sha1': f'{i:040x}', 'dns': [f'host{i}.example']}


class TestRetryCap(unittest.TestCase):
    def test_writer_waits_at_the_cap_and_resumes_when_es_accepts(self):
        es = make_es()
        for i in range(30):                      # 3 batches refused -> 30 docs waiting = the cap
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')
        self.assertEqual(es.pending_retry_docs(), 30)

        sleeps = []

        def sleep(secs):
            sleeps.append(secs)
            if len(sleeps) == 3:                 # Elasticsearch comes back after a few seconds
                es.session.status = 200
        es._sleep = sleep
        es.add_to_batch(doc(30), 'https://ct.googleapis.com/logs/x/')

        self.assertGreaterEqual(len(sleeps), 3, 'the writer must wait while the retry list is full')
        self.assertEqual(es.pending_retry_docs(), 0)
        self.assertEqual(es.stats['created'], 30)
        self.assertEqual(len(es.batch), 1)       # the new document went in after the wait

    def test_pending_never_exceeds_cap_plus_one_batch(self):
        es = make_es()
        stop = {'now': False}
        es.should_stop = lambda: stop['now']
        waits = []

        def sleep(secs):
            waits.append(secs)
            if len(waits) > 20:
                stop['now'] = True
        es._sleep = sleep
        for i in range(200):
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')
            self.assertLessEqual(es.pending_retry_docs(), es.retry_max_docs + es.batch_size)
            if stop['now']:
                break
        self.assertTrue(waits, 'expected the writer to block once the cap was reached')

    def test_shutdown_releases_a_waiting_writer(self):
        es = make_es()
        for i in range(30):
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')
        es.should_stop = lambda: True
        t0 = time.monotonic()
        es.add_to_batch(doc(99), 'https://ct.googleapis.com/logs/x/')   # must not hang
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_retry_stops_at_the_first_refused_batch_and_keeps_order(self):
        es = make_es(retry_max_docs=10 ** 6)
        for i in range(50):
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')
        before = [list(b) for b in es.failed_batches]
        self.assertEqual(len(before), 5)
        posts = es.session.posts
        es.retry_failed_batches()
        self.assertEqual(es.session.posts - posts, 1, 'one request per attempt while ES still refuses')
        self.assertEqual(es.failed_batches, before)

    def test_retry_does_not_touch_the_batch_being_filled(self):
        es = make_es(retry_max_docs=10 ** 6)
        for i in range(10):
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')   # one refused batch
        for i in range(10, 15):
            es.add_to_batch(doc(i), 'https://ct.googleapis.com/logs/x/')   # 5 docs being filled
        filling = list(es.batch)
        es.session.status = 200
        es.retry_failed_batches()
        self.assertEqual(es.batch, filling)
        self.assertEqual(es.pending_retry_docs(), 0)
        self.assertEqual(es.stats['created'], 10)


class TestBoundedQueuePut(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('ctm', HERE / 'ct-monitor.py')
        cls.ctm = importlib.util.module_from_spec(spec)
        argv, sys.argv = sys.argv, ['ct-monitor']
        spec.loader.exec_module(cls.ctm)
        sys.argv = argv

    def test_put_waits_for_room(self):
        stub = MagicMock(shutdown_event=threading.Event())
        q = queue.Queue(maxsize=1)
        q.put('first')
        threading.Timer(0.3, q.get).start()
        self.assertTrue(self.ctm.CTLogMonitor._put(stub, q, 'second'))
        self.assertEqual(q.get_nowait(), 'second')

    def test_put_on_a_full_queue_returns_on_shutdown(self):
        stub = MagicMock(shutdown_event=threading.Event())
        q = queue.Queue(maxsize=1)
        q.put('first')
        threading.Timer(0.3, stub.shutdown_event.set).start()
        t0 = time.monotonic()
        self.assertFalse(self.ctm.CTLogMonitor._put(stub, q, 'second'))
        self.assertLess(time.monotonic() - t0, 2.5)


if __name__ == '__main__':
    unittest.main()
