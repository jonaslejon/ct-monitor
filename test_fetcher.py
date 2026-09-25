#!/usr/bin/env python3
"""Tests for fetcher.py: gap-free range fetching and the persisted cursor."""

import json
import os
import tempfile
import threading
import unittest

from fetcher import PositionStore, RangeFetcher


class ShortPageLog:
    """A log that returns at most `page` entries per request, like logs that cap get-entries
    at an internal boundary. Entries are their own index, so gaps and duplicates are visible."""

    def __init__(self, page=19, fail_at=None, fail_times=0):
        self.page = page
        self.fail_at = fail_at
        self.fail_times = fail_times
        self.calls = 0
        self.lock = threading.Lock()

    def get_entries(self, start, end):
        with self.lock:
            self.calls += 1
            if self.fail_at is not None and start <= self.fail_at <= end and self.fail_times > 0:
                self.fail_times -= 1
                raise IOError('boom')
        return [{'i': i} for i in range(start, min(end + 1, start + self.page))]


def collect():
    seen = []
    lock = threading.Lock()

    def on_entry(e):
        with lock:
            seen.append(e['i'])
    return seen, on_entry


class TestRangeFetcher(unittest.TestCase):
    def test_short_pages_are_fetched_without_gaps(self):
        log = ShortPageLog(page=19)
        seen, on_entry = collect()
        f = RangeFetcher(log.get_entries, on_entry, workers=1, sleep=lambda s: None)
        self.assertEqual(f.fetch(1000, 3000), 3000)
        self.assertEqual(sorted(seen), list(range(1000, 3000)))

    def test_the_old_loop_would_have_skipped_most_of_this_log(self):
        # Regression guard for the bug being fixed: advancing by the requested 100.
        log = ShortPageLog(page=19)
        got = []
        for idx in range(0, 1000, 100):
            got += [e['i'] for e in log.get_entries(idx, idx + 99)]
        self.assertEqual(len(got), 190)

    def test_parallel_fetch_is_complete_and_reports_a_monotonic_contiguous_cursor(self):
        log = ShortPageLog(page=7)
        seen, on_entry = collect()
        progress = []
        f = RangeFetcher(log.get_entries, on_entry, workers=4, range_size=100, sleep=lambda s: None)
        self.assertEqual(f.fetch(0, 1050, on_progress=progress.append), 1050)
        self.assertEqual(sorted(seen), list(range(1050)))
        self.assertEqual(progress, sorted(progress))
        self.assertEqual(progress[-1], 1050)

    def test_a_transient_failure_is_retried_at_the_same_index(self):
        log = ShortPageLog(page=19, fail_at=500, fail_times=2)
        seen, on_entry = collect()
        f = RangeFetcher(log.get_entries, on_entry, workers=1, max_retries=5, sleep=lambda s: None)
        self.assertEqual(f.fetch(0, 1000), 1000)
        self.assertEqual(sorted(seen), list(range(1000)))

    def test_a_persistent_failure_stops_the_cursor_before_the_hole(self):
        log = ShortPageLog(page=50, fail_at=450, fail_times=10**6)
        seen, on_entry = collect()
        f = RangeFetcher(log.get_entries, on_entry, workers=3, range_size=100,
                         max_retries=3, sleep=lambda s: None)
        cursor = f.fetch(0, 1000)
        self.assertEqual(cursor, 400)          # [400,500) failed: cursor must not pass it
        self.assertTrue(set(range(400)) <= set(seen))

    def test_empty_pages_are_retried_not_treated_as_done(self):
        calls = {'n': 0}

        def flaky(a, b):
            calls['n'] += 1
            return [] if calls['n'] == 1 else [{'i': i} for i in range(a, b + 1)]
        seen, on_entry = collect()
        f = RangeFetcher(flaky, on_entry, sleep=lambda s: None)
        self.assertEqual(f.fetch(0, 10), 10)
        self.assertEqual(sorted(seen), list(range(10)))

    def test_entries_beyond_the_requested_window_are_ignored(self):
        def generous(a, b):
            return [{'i': i} for i in range(a, b + 50)]
        seen, on_entry = collect()
        f = RangeFetcher(generous, on_entry, request_size=10, sleep=lambda s: None)
        self.assertEqual(f.fetch(0, 25), 25)
        self.assertEqual(sorted(seen), list(range(25)))

    def test_shutdown_returns_the_contiguous_cursor(self):
        stop = threading.Event()

        def get(a, b):
            if a >= 300:
                stop.set()
            return [{'i': i} for i in range(a, b + 1)]
        seen, on_entry = collect()
        f = RangeFetcher(get, on_entry, request_size=100, range_size=100,
                         shutdown_event=stop, sleep=lambda s: None)
        cursor = f.fetch(0, 1000)
        self.assertLessEqual(cursor, 400)
        self.assertEqual(sorted(seen)[:cursor], list(range(cursor)))


class TestPositionStore(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state', 'positions.json')
            s = PositionStore(path, flush_interval=0)
            s.set('https://log.example/a/', 123)
            s.flush()
            self.assertEqual(PositionStore(path).get('https://log.example/a/'), 123)

    def test_writes_are_throttled_but_flush_forces(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'positions.json')
            s = PositionStore(path, flush_interval=3600)
            s.set('u', 1)                    # first write goes through (last_flush was 0)
            s.set('u', 2)                    # throttled
            self.assertEqual(PositionStore(path).get('u'), 1)
            s.flush()
            self.assertEqual(PositionStore(path).get('u'), 2)

    def test_a_corrupt_file_starts_empty_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'positions.json')
            with open(path, 'w') as f:
                f.write('{not json')
            self.assertIsNone(PositionStore(path).get('u'))

    def test_no_path_means_no_persistence(self):
        s = PositionStore(None)
        s.set('u', 5)
        s.flush()
        self.assertEqual(s.get('u'), 5)


if __name__ == '__main__':
    unittest.main()
