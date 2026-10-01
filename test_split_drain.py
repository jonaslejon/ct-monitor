"""Tests for log selection (--logs / --exclude-logs) and the graceful SIGTERM drain.

Why the drain exists: the saved cursor counts ENQUEUED entries, so an instant stop lost whatever
sat in the bounded queues on every restart. A graceful stop stops the fetchers, lets the workers
and the writer finish, then saves the cursors.

Run:  python3 -m unittest test_split_drain
"""
import importlib.util
import os
import threading
import time
import unittest

_spec = importlib.util.spec_from_file_location(
    'ctmon_under_test', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ct-monitor.py'))
ctm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctm)

LOGS = [
    'https://ct.googleapis.com/logs/us1/argon2026h2/',
    'https://ct.googleapis.com/logs/us1/argon2027h1/',
    'https://ct.googleapis.com/logs/eu1/xenon2026h2/',
    'https://ct.cloudflare.com/logs/nimbus2026/',
    'https://tiger2026h2.ct.sectigo.com/',
    'https://wyvern.ct.digicert.com/2026h2/',
    'https://ct2026-a.trustasia.com/log2026a/',
]
SPLIT = {'argon': ('argon', None), 'xenon': ('xenon', None),
         'nimbus-sectigo': ('nimbus,sectigo', None),
         'rest': (None, 'argon,xenon,nimbus,sectigo')}


def _mon():
    return ctm.CTLogMonitor(quiet=True)


class FilterLogsTest(unittest.TestCase):
    f = staticmethod(ctm.CTLogMonitor.filter_logs)

    def test_no_filter_keeps_all(self):
        self.assertEqual(self.f(LOGS, None, None), LOGS)

    def test_include_matches_any_substring(self):
        self.assertEqual(self.f(LOGS, 'argon', None), LOGS[:2])
        self.assertEqual(self.f(LOGS, 'nimbus, sectigo', None), [LOGS[3], LOGS[4]])

    def test_exclude_after_include(self):
        self.assertEqual(self.f(LOGS, 'googleapis', 'argon2027'), [LOGS[0], LOGS[2]])

    def test_the_four_units_cover_every_log_exactly_once(self):
        seen = []
        for inc, exc in SPLIT.values():
            seen += self.f(LOGS, inc, exc)
        self.assertEqual(sorted(seen), sorted(LOGS))

    def test_a_new_log_lands_in_the_catch_all(self):
        new = LOGS + ['https://newop2027.example-ct.org/']
        inc, exc = SPLIT['rest']
        self.assertIn(new[-1], self.f(new, inc, exc))

    def test_unknown_substring_selects_nothing(self):
        self.assertEqual(self.f(LOGS, 'nosuchlog', None), [])


class DrainTest(unittest.TestCase):
    def _start(self, mon, n=2, target=None):
        ts = [threading.Thread(target=target or mon.worker_thread, daemon=True) for _ in range(n)]
        for t in ts:
            t.start()
        return ts

    def tearDown(self):
        if getattr(self, 'mon', None):
            self.mon.fetch_stop_event.set()
            self.mon.shutdown_event.set()

    def test_drain_finishes_queued_work_and_leaves_workers_running(self):
        self.mon = mon = _mon()
        mon.process_certificate = lambda e: (time.sleep(0.001), [])[1]
        for i in range(300):
            mon.input_queue.put({'i': i})
        self._start(mon)
        self.assertTrue(mon.graceful_drain(10))
        self.assertEqual(mon.input_queue.unfinished_tasks, 0)
        self.assertTrue(mon.fetch_stop_event.is_set())
        self.assertFalse(mon.shutdown_event.is_set())   # the full stop is the caller's next step

    def test_a_poison_entry_does_not_hang_the_drain(self):
        self.mon = mon = _mon()

        def proc(e):
            if e.get('bad'):
                raise ValueError('unparseable')
            return []
        mon.process_certificate = proc
        for i in range(50):
            mon.input_queue.put({'bad': i % 7 == 0})
        self._start(mon)
        self.assertTrue(mon.graceful_drain(10))

    def test_deadline_reports_failure_instead_of_hanging(self):
        self.mon = mon = _mon()
        for i in range(5):
            mon.input_queue.put({'i': i})   # no workers: nothing will ever take these
        t0 = time.monotonic()
        self.assertFalse(mon.graceful_drain(0.5))
        self.assertLess(time.monotonic() - t0, 3)

    def test_output_thread_counts_a_failed_item_as_done(self):
        self.mon = mon = _mon()

        class Bad:
            name = 'x.example'

            def to_dict(self):
                raise RuntimeError('broken result')
        mon.output_queue.put(Bad())
        self._start(mon, n=1, target=mon.output_thread)
        deadline = time.monotonic() + 5
        while mon.output_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(mon.output_queue.unfinished_tasks, 0)

    def test_drain_waits_for_the_dns_queue_and_flushes_it(self):
        self.mon = mon = _mon()

        class FakeDNS:
            def __init__(self):
                self.queue, self.flushes = 30, 0

            def get_queue_stats(self):
                return {'queue_size': self.queue, 'active_workers': 0}

            def _trigger_flush(self):
                self.flushes += 1
                self.queue = max(0, self.queue - 10)
        mon.dns_resolve, mon.dns_resolver_thread = True, FakeDNS()
        self.assertTrue(mon.graceful_drain(10))
        self.assertEqual(mon.dns_resolver_thread.queue, 0)
        self.assertGreaterEqual(mon.dns_resolver_thread.flushes, 3)

    def test_a_dns_backlog_does_not_hold_the_stop(self):
        self.mon = mon = _mon()

        class SlowDNS:
            def get_queue_stats(self):
                return {'queue_size': 700_000, 'active_workers': 50}

            def _trigger_flush(self):
                pass
        mon.dns_resolve, mon.dns_resolver_thread = True, SlowDNS()
        old = os.environ.get('CT_DRAIN_DNS_TIMEOUT')
        os.environ['CT_DRAIN_DNS_TIMEOUT'] = '0.5'
        try:
            t0 = time.monotonic()
            self.assertTrue(mon.graceful_drain(60))   # entries and results are empty: a success
            self.assertLess(time.monotonic() - t0, 5)
        finally:
            if old is None:
                os.environ.pop('CT_DRAIN_DNS_TIMEOUT')
            else:
                os.environ['CT_DRAIN_DNS_TIMEOUT'] = old

    def test_an_unreadable_dns_queue_does_not_abort_the_drain(self):
        self.mon = mon = _mon()

        class BrokenDNS:
            def get_queue_stats(self):
                raise RuntimeError('no stats')
        mon.dns_resolve, mon.dns_resolver_thread = True, BrokenDNS()
        mon.process_certificate = lambda e: []
        for i in range(20):
            mon.input_queue.put({'i': i})
        self._start(mon)
        self.assertTrue(mon.graceful_drain(10))
        self.assertEqual(mon.input_queue.unfinished_tasks, 0)

    def test_the_real_dns_thread_has_the_methods_the_drain_calls(self):
        # Wiring: the 2026-10-01 production drain crashed calling a method DNSResolverThread lacks.
        import dns_resolver
        for name in ('get_queue_stats', '_trigger_flush'):
            self.assertTrue(callable(getattr(dns_resolver.DNSResolverThread, name, None)), name)

    def test_drain_freezes_the_cursors_before_draining(self):
        import json, tempfile
        d = tempfile.mkdtemp()
        self.mon = mon = ctm.CTLogMonitor(quiet=True, state_file=os.path.join(d, 'p.json'))
        mon.position_store.set('https://log.example/', 100)
        self.assertTrue(mon.graceful_drain(5))
        mon.position_store.set('https://log.example/', 999)   # a range that completed after the stop began
        mon.position_store.flush(force=True)
        with open(os.path.join(d, 'p.json')) as f:
            self.assertEqual(json.load(f)['positions']['https://log.example/'], 100)

    def test_a_slow_fetch_does_not_hold_the_stop(self):
        self.mon = mon = _mon()
        import concurrent.futures
        never = concurrent.futures.Future()             # a fetcher stuck in a slow request
        mon._log_futures = [never]
        os.environ['CT_DRAIN_FETCH_WAIT'] = '0.5'
        try:
            t0 = time.monotonic()
            self.assertTrue(mon.graceful_drain(60))
            self.assertLess(time.monotonic() - t0, 5)
        finally:
            os.environ.pop('CT_DRAIN_FETCH_WAIT')

    def test_the_progress_line_reports_lag_against_the_live_head(self):
        self.mon = mon = ctm.CTLogMonitor(quiet=True)          # one pass (no -f)
        heads = iter([10_000, 15_000])                       # pass start, then the live head after the pass
        mon.get_sth = lambda url: {'tree_size': next(heads, 15_000)}
        mon.http_client.fetch_json_once = lambda url: {'entries': [{'leaf_input': '', 'extra_data': ''}] * 50}
        lines = []
        mon.logger.warning = lambda msg, force=False: lines.append(msg)
        mon.monitor_log_v2('https://log.example/ct/')
        line = [l for l in lines if l.startswith('📍')][-1]
        self.assertIn('head=15000', line)
        self.assertIn('lag=5000', line)

    def test_gap_free_fetcher_stops_on_fetch_stop_alone(self):
        # follow=True: without it monitor_log_v2 makes one pass and returns whatever the stop logic does
        self.mon = mon = ctm.CTLogMonitor(quiet=True, follow=True)
        calls = []
        mon.get_sth = lambda url: {'tree_size': 10_000}

        def fake_fetch(url):
            calls.append(url)
            if len(calls) >= 3:
                mon.fetch_stop_event.set()
            return {'entries': [{'leaf_input': '', 'extra_data': ''}] * 5}
        mon.http_client.fetch_json_once = fake_fetch
        t = threading.Thread(target=mon.monitor_log_v2, args=('https://log.example/ct/',), daemon=True)
        t.start()
        t.join(15)
        self.assertFalse(t.is_alive(), 'fetcher kept running after fetch_stop_event')
        self.assertFalse(mon.shutdown_event.is_set())
        self.assertGreaterEqual(len(calls), 3)


if __name__ == '__main__':
    unittest.main()
