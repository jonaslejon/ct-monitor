"""Tests for the 2026-10-01 DNS fixes: first sightings only, no wildcard guesses, continuous lookups,
a host-keyed cache, and the stats file.

Run:  python3 -m unittest test_dns_pipeline
"""
import asyncio
import importlib.util
import json
import os
import queue
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import dns_resolver
import elasticsearch_output
from dns_resolver import DNSResolver, DNSResolverThread, DNSResult

_spec = importlib.util.spec_from_file_location(
    'ctmon_dns_test', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ct-monitor.py'))
ctm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctm)


class QuietLog:
    def __getattr__(self, name):
        return lambda *a, **k: None


def _thread(**kw):
    return DNSResolverThread(logger=QuietLog(), **kw)


class WildcardTest(unittest.TestCase):
    def test_a_wildcard_resolves_its_base_only(self):
        self.assertEqual(DNSResolver.names_for('*.example.com'), ['example.com'])
        self.assertEqual(DNSResolver.names_for('mail.example.com'), ['mail.example.com'])

    def test_resolve_batch_never_guesses_www_or_mail(self):
        r = DNSResolver(QuietLog())
        asked = []

        async def fake(name, sha1=None):
            asked.append(name)
            return DNSResult(domain=name, ips=['192.0.2.1'], cert_sha1=sha1)
        r.resolve_domain_async = fake
        asyncio.run(r.resolve_batch([('*.cobound.example', 'c1'), ('cobound.example', 'c1')]))
        self.assertNotIn('www.cobound.example', asked)
        self.assertNotIn('mail.cobound.example', asked)
        self.assertIn('cobound.example', asked)


class CacheTest(unittest.TestCase):
    def test_same_host_from_two_certificates_is_one_query_and_two_bound_results(self):
        r = DNSResolver(QuietLog(), cache_size=100, cache_ttl=900)
        calls = []

        class FakeAnswer(list):
            response = type('R', (), {'answer': []})()

        async def resolve(name, rdtype):
            calls.append(name)
            return FakeAnswer(['192.0.2.7'])
        r.get_next_resolver = lambda: type('X', (), {'resolve': staticmethod(resolve), 'nameservers': ['127.0.0.1'], 'port': 53})()
        a = asyncio.run(r.resolve_domain_async('host.example', 'certA'))
        b = asyncio.run(r.resolve_domain_async('host.example', 'certB'))
        self.assertEqual(calls, ['host.example'])
        self.assertEqual((a.cert_sha1, b.cert_sha1), ('certA', 'certB'))
        self.assertEqual(b.ips, ['192.0.2.7'])
        self.assertNotEqual(a.to_es_doc()['h'], b.to_es_doc()['h'])   # still one document per certificate

    def test_cache_size_and_ttl_reach_the_resolver(self):
        t = _thread(cache_size=1234, cache_ttl=900)
        self.assertEqual((t.resolver.cache.max_size, t.resolver.cache.ttl_seconds), (1234, 900))


class TimeoutClassTest(unittest.TestCase):
    def test_a_lifetime_expiry_is_a_timeout(self):
        class LifetimeTimeout(Exception):
            pass
        r = DNSResolver(QuietLog())
        self.assertEqual(r._classify_error(LifetimeTimeout('The resolution lifetime expired after 4.001 seconds')), 'timeout')
        self.assertEqual(r._classify_error(Exception('The DNS query name does not exist: x.')), 'nxdomain')


class ContinuousTest(unittest.TestCase):
    def test_one_slow_lookup_does_not_hold_back_the_rest(self):
        t = _thread(max_concurrent=10, num_workers=1)
        t.storage = object()   # results are queued, never flushed (fewer than 1000)

        async def fake(name, sha1=None):
            await asyncio.sleep(3.0 if name == 'slow.example' else 0.01)
            return DNSResult(domain=name, ips=['192.0.2.1'], cert_sha1=sha1)
        t.resolver.resolve_domain_async = fake
        t.queue.append(('slow.example', 'c'))
        for i in range(300):
            t.queue.append((f'h{i}.example', 'c'))
        with t.workers_lock:
            t.active_workers += 1
        th = threading.Thread(target=t._run_batch_resolution, daemon=True)
        th.start()
        time.sleep(1.5)
        # batches of 500 returned nothing until the slow one finished; slots keep going without it
        self.assertGreaterEqual(t.resolved_total, 250)
        th.join(10)
        self.assertEqual(t.resolved_total, 301)
        self.assertEqual(t.active_workers, 0)

    def test_an_exception_does_not_kill_the_slot(self):
        t = _thread(max_concurrent=1, num_workers=1)

        async def fake(name, sha1=None):
            if name == 'boom.example':
                raise RuntimeError('boom')
            return DNSResult(domain=name, ips=[], cert_sha1=sha1)
        t.resolver.resolve_domain_async = fake
        for n in ('boom.example', 'a.example', 'b.example'):
            t.queue.append((n, 'c'))
        with t.workers_lock:
            t.active_workers += 1
        t._run_batch_resolution()
        self.assertEqual(t.resolved_total, 2)


class FirstSightingTest(unittest.TestCase):
    def _es(self, statuses):
        with patch('elasticsearch_output.requests.Session', return_value=MagicMock()):
            es = elasticsearch_output.ElasticsearchOutput(es_host='http://es.invalid:9200', batch_size=100)

        class Resp:
            status_code = 200
            text = ''

            def json(self_inner):
                return {'errors': False, 'items': [{'index': {'status': s}} for s in statuses]}
        es.session = MagicMock()
        es.session.post.return_value = Resp()
        return es

    def test_only_created_documents_are_handed_to_dns(self):
        es = self._es([201, 200, 409, 201])
        got = []
        es.on_created = lambda d, h: got.append((d, h))
        batch = [('ct-domains-x', f'id{i}', {'d': f'n{i}.example', 'h': f'sha{i}'}, 'index') for i in range(4)]
        es._send(batch)
        self.assertEqual(got, [('n0.example', 'sha0'), ('n3.example', 'sha3')])

    def test_a_failing_callback_does_not_break_the_writer(self):
        es = self._es([201])
        es.on_created = MagicMock(side_effect=RuntimeError('dns down'))
        self.assertTrue(es._send([('ct-domains-x', 'id', {'d': 'a.example', 'h': 's'}, 'index')]))

    def test_output_thread_leaves_dns_to_the_writer_when_es_is_on(self):
        mon = ctm.CTLogMonitor(quiet=True)
        mon.es_output, mon.dns_resolve = True, True
        mon.dns_resolver_thread = MagicMock()
        mon.es_output_handler = MagicMock()
        mon.output_queue.put(ctm.CTResult(name='a.example', timestamp=0, cn='a.example', sha1='s',
                                          dns=['b.example']))
        th = threading.Thread(target=mon.output_thread, daemon=True)
        th.start()
        deadline = time.monotonic() + 5
        while mon.output_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.05)
        mon.shutdown_event.set()
        th.join(3)
        mon.es_output_handler.add_to_batch.assert_called_once()
        mon.dns_resolver_thread.add_domain.assert_not_called()


class StatsTest(unittest.TestCase):
    def test_stats_file_is_written_next_to_the_state_file(self):
        d = tempfile.mkdtemp()
        mon = ctm.CTLogMonitor(quiet=True, state_file=os.path.join(d, 'positions-x.json'))
        mon.dns_resolver_thread = MagicMock()
        mon.dns_resolver_thread.get_queue_stats.return_value = {
            'queue_size': 7, 'max_queue_size': 1000000, 'dropped_domains': 0, 'storage_queue_size': 1,
            'resolved_total': 50, 'resolver_stats': {'cache_stats': {'hit_rate': 12.5}}}
        th = threading.Thread(target=mon._dns_stats_loop, args=(0.1,), daemon=True)
        th.start()
        time.sleep(0.5)
        mon.shutdown_event.set()
        th.join(2)
        with open(os.path.join(d, 'stats-positions-x.json')) as fh:
            doc = json.load(fh)
        self.assertEqual((doc['queue_size'], doc['max_queue_size'], doc['dropped_domains']), (7, 1000000, 0))
        self.assertEqual(doc['cache_hit_rate'], 12.5)


if __name__ == '__main__':
    unittest.main()
