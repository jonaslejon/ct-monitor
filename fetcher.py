"""
Gap-free CT log fetching and a persisted per-log cursor.

Why this exists: RFC 6962 lets a log return FEWER entries than get-entries asked for, and several
large logs do so on every request (Google's logs return roughly 7-30 entries whatever the request
size). A loop that advances by the requested batch size therefore skips most of such a log. The
fetcher here always advances by the number of entries actually returned, can fetch several ranges
of one log in parallel, and only reports progress over a CONTIGUOUS completed prefix, so a slow or
failed range can never let the cursor move past a hole.

PositionStore keeps each log's cursor on disk so a restart resumes where it stopped instead of
jumping to the head of the log.
"""

import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional


class RangeFailed(Exception):
    """A range could not be fetched after retries; the cursor stops before it."""


class PositionStore:
    """Per-log next-index cursor, persisted atomically (temp file + rename)."""

    def __init__(self, path: Optional[str], flush_interval: float = 10.0):
        self.path = path
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        self._positions: Dict[str, int] = {}
        self._dirty = False
        self._last_flush = 0.0
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                self._positions = {k: int(v) for k, v in data.get('positions', {}).items()}
            except (OSError, ValueError, AttributeError):
                # A corrupt state file must not stop monitoring; start from the head instead.
                self._positions = {}

    def get(self, log_url: str) -> Optional[int]:
        with self._lock:
            return self._positions.get(log_url)

    def set(self, log_url: str, next_index: int) -> None:
        with self._lock:
            if self._positions.get(log_url) != next_index:
                self._positions[log_url] = next_index
                self._dirty = True
        self.flush(force=False)

    def flush(self, force: bool = True) -> None:
        if not self.path:
            return
        with self._lock:
            if not self._dirty:
                return
            if not force and time.time() - self._last_flush < self.flush_interval:
                return
            snapshot = dict(self._positions)
            self._dirty = False
            self._last_flush = time.time()
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix='.positions-')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump({'positions': snapshot, 'saved_at': int(time.time())}, f)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            with self._lock:
                self._dirty = True


class RangeFetcher:
    """Fetch [start, end) of one log without gaps.

    get_entries(start, end_inclusive) -> list of entries (may return fewer than asked).
    on_entry(entry) is called for every entry exactly once per successful fetch.
    """

    def __init__(self, get_entries: Callable[[int, int], List[Dict]],
                 on_entry: Callable[[Dict], None],
                 workers: int = 1, range_size: int = 1024, request_size: int = 256,
                 max_retries: int = 5, retry_sleep: float = 5.0,
                 shutdown_event: Optional[threading.Event] = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.get_entries = get_entries
        self.on_entry = on_entry
        self.workers = max(1, int(workers))
        self.range_size = max(1, int(range_size))
        self.request_size = max(1, int(request_size))
        self.max_retries = max(1, int(max_retries))
        self.retry_sleep = retry_sleep
        self.shutdown_event = shutdown_event or threading.Event()
        self.sleep = sleep

    def _fetch_range(self, a: int, b: int) -> int:
        """Fetch [a, b). Returns b on success; raises RangeFailed or returns early on shutdown."""
        pos = a
        failures = 0
        while pos < b:
            if self.shutdown_event.is_set():
                return pos
            end = min(pos + self.request_size, b) - 1
            try:
                entries = self.get_entries(pos, end)
            except Exception as e:  # network, bad JSON, error_message: retry the SAME position
                entries = None
                last_error = e
            if not entries:
                failures += 1
                if failures >= self.max_retries:
                    raise RangeFailed(f"no entries at index {pos} after {failures} attempts"
                                      + (f": {last_error}" if entries is None else ""))
                self.sleep(self.retry_sleep)
                continue
            failures = 0
            # Never trust a log to stay inside the requested window.
            entries = entries[:end - pos + 1]
            for entry in entries:
                self.on_entry(entry)
            pos += len(entries)
        return pos

    def fetch(self, start: int, end: int,
              on_progress: Optional[Callable[[int], None]] = None) -> int:
        """Fetch [start, end). Returns the new contiguous cursor (== end when complete)."""
        if end <= start:
            return start
        ranges = [(a, min(a + self.range_size, end)) for a in range(start, end, self.range_size)]
        cursor = start
        if self.workers == 1:
            for a, b in ranges:
                try:
                    reached = self._fetch_range(a, b)
                except RangeFailed:
                    return cursor
                cursor = reached
                if on_progress:
                    on_progress(cursor)
                if reached < b:  # shutdown
                    return cursor
            return cursor

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(self._fetch_range, a, b) for a, b in ranges]
            broken = False
            for (a, b), fut in zip(ranges, futures):
                if broken:
                    fut.cancel()
                    continue
                try:
                    reached = fut.result()
                except RangeFailed:
                    broken = True
                    continue
                cursor = reached
                if on_progress:
                    on_progress(cursor)
                if reached < b:  # shutdown mid-range
                    broken = True
        return cursor
