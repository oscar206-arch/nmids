"""
alert_module.py
Receives anomaly dicts from the detection engine.
  1. Persists them to the alerts table via logging_module
  2. Pushes real-time SSE events to subscribed browser clients
  3. Maintains an in-memory ring buffer for late-joining clients
"""

import json
import queue
import threading
from datetime import datetime

import backend.logging_module as db

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
MAX_BUFFER     = 200   # in-memory alert ring buffer size


class AlertModule:

    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._sub_lock    = threading.Lock()
        self._buffer: list[dict] = []          # recent alerts for new subscribers
        self._buffer_lock = threading.Lock()

    # ─── Called by detection engine ───────────────────────────────────────────

    def dispatch(self, alert: dict):
        """Persist alert and push to all SSE subscribers."""
        # Persist
        alert_id = db.log_alert(alert)
        alert['id'] = alert_id

        # Buffer
        with self._buffer_lock:
            self._buffer.append(alert)
            if len(self._buffer) > MAX_BUFFER:
                self._buffer = self._buffer[-MAX_BUFFER:]

        # Push SSE
        payload = json.dumps(alert)
        with self._sub_lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    # ─── SSE subscription management ─────────────────────────────────────────

    def subscribe(self) -> queue.Queue:
        """Return a new Queue that will receive alert JSON strings."""
        q = queue.Queue(maxsize=50)
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def get_buffer(self) -> list[dict]:
        """Return recent alerts for a newly connected client."""
        with self._buffer_lock:
            return list(self._buffer)

    # ─── SSE event stream generator ───────────────────────────────────────────

    def event_stream(self):
        """
        Generator used by Flask's /api/stream endpoint.
        Yields SSE-formatted strings indefinitely.
        """
        q = self.subscribe()
        # Send buffered alerts first so client sees recent history
        with self._buffer_lock:
            for alert in self._buffer[-20:]:
                yield f"data: {json.dumps(alert)}\n\n"
        try:
            while True:
                try:
                    payload = q.get(timeout=20)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"   # keep connection alive
        except GeneratorExit:
            pass
        finally:
            self.unsubscribe(q)

    # ─── Packet stream for live feed ─



class PacketFeed:
    """
    Separate SSE feed that pushes every packet (not just alerts) to the
    Dashboard live packet table.
    """

    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def push(self, packet: dict):
        import json
        payload = json.dumps(packet)
        with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def event_stream(self):
        import json
        q = self.subscribe()
        try:
            while True:
                try:
                    payload = q.get(timeout=20)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            self.unsubscribe(q)
