#
# Copyright 2014 Nebula, Inc
# Copyright 2014 Justin Santa Barbara
# Copyright 2014 Symantec Corporation
# Copyright 2013-2014 DataStax, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import errno
import functools
import logging
import os
import threading

import eventlet
from eventlet import green
from eventlet import queue


try:
    from cStringIO import StringIO  # ignore flake8 warning: # NOQA
except ImportError:
    from StringIO import StringIO  # ignore flake8 warning: # NOQA

import cassandra
from cassandra import connection
from cassandra import marshal
from cassandra import protocol


log = logging.getLogger(__name__)


def is_timeout(err):
    return (err in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK) or
            (err == errno.EINVAL and os.name in ('nt', 'ce')))


class EventletConnection(connection.Connection):
    """An implementation of :class:`.Connection` that utilizes ``eventlet``."""

    _total_reqd_bytes = 0
    _read_watcher = None
    _write_watcher = None
    _socket = None

    @classmethod
    def factory(cls, *args, **kwargs):
        timeout = kwargs.pop('timeout', 5.0)
        conn = cls(*args, **kwargs)
        conn.connected_event.wait(timeout)
        if conn.last_error:
            raise conn.last_error
        elif not conn.connected_event.is_set():
            conn.close()
            raise cassandra.OperationTimedOut("Timed out creating connection")
        else:
            return conn

    def __init__(self, *args, **kwargs):
        connection.Connection.__init__(self, *args, **kwargs)

        self.connected_event = threading.Event()
        self._iobuf = StringIO()
        self._write_queue = queue.Queue()

        self._callbacks = {}
        self._push_watchers = collections.defaultdict(set)

        self._socket = green.socket.socket(green.socket.AF_INET,
                                           green.socket.SOCK_STREAM)
        self._socket.settimeout(1.0)
        self._socket.connect((self.host, self.port))

        if self.sockopts:
            for args in self.sockopts:
                self._socket.setsockopt(*args)

        self._read_watcher = eventlet.spawn(lambda: self.handle_read())
        self._write_watcher = eventlet.spawn(lambda: self.handle_write())

        self._send_options_message()

    def close(self):
        with self.lock:
            if self.is_closed:
                return
            self.is_closed = True

        log.debug("Closing connection (%s) to %s" % (id(self), self.host))

        cur_gthread = eventlet.getcurrent()

        if self._read_watcher and self._read_watcher != cur_gthread:
            self._read_watcher.kill()
            # Avoid refcycles
            self._read_watcher = None
        if self._write_watcher and self._write_watcher != cur_gthread:
            self._write_watcher.kill()
            # Avoid refcycles
            self._write_watcher = None
        if self._socket:
            self._socket.close()
            self._socket = None
        log.debug("Closed socket to %s" % (self.host,))

        if not self.is_defunct:
            self.error_all_callbacks(
                connection.ConnectionShutdown("Connection to %s was closed"
                                              % self.host))
            # don't leave in-progress operations hanging
            self.connected_event.set()

    def handle_write(self):
        while True:
            try:
                next_msg = self._write_queue.get()
                self._socket.send(next_msg)
            except green.socket.error as err:
                log.debug(
                    "Exception during socket sendall for %s: %s", self, err)
                self.defunct(err)
                return  # Leave the write loop

    def handle_read(self):
        run_select = functools.partial(green.select.select,
                                       (self._socket,), (), ())
        while True:
            try:
                run_select()
            except Exception as exc:
                if not self.is_closed:
                    log.debug(
                        "Exception during read select() for %s: %s", self, exc)
                    self.defunct(exc)
                return

            try:
                buf = self._socket.recv(self.in_buffer_size)
                self._iobuf.write(buf)
            except green.socket.error as err:
                if not is_timeout(err):
                    log.debug(
                        "Exception during socket recv for %s: %s", self, err)
                    self.defunct(err)
                    return  # leave the read loop

            if self._iobuf.tell():
                while True:
                    pos = self._iobuf.tell()
                    if pos < 8 or (self._total_reqd_bytes > 0
                                   and pos < self._total_reqd_bytes):
                        # we don't have a complete header yet or we
                        # already saw a header, but we don't have a
                        # complete message yet
                        break
                    else:
                        # have enough for header, read body len from header
                        self._iobuf.seek(4)
                        body_len = marshal.int32_unpack(self._iobuf.read(4))

                        # seek to end to get length of current buffer
                        self._iobuf.seek(0, os.SEEK_END)
                        pos = self._iobuf.tell()

                        if pos >= body_len + 8:
                            # read message header and body
                            self._iobuf.seek(0)
                            msg = self._iobuf.read(8 + body_len)

                            # leave leftover in current buffer
                            leftover = self._iobuf.read()
                            self._iobuf = StringIO()
                            self._iobuf.write(leftover)

                            self._total_reqd_bytes = 0
                            self.process_msg(msg, body_len)
                        else:
                            self._total_reqd_bytes = body_len + 8
                            break
            else:
                log.debug("connection closed by server")
                self.close()
                return

    def push(self, data):
        chunk_size = self.out_buffer_size
        for i in xrange(0, len(data), chunk_size):
            self._write_queue.put(data[i:i + chunk_size])

    def register_watcher(self, event_type, callback, register_timeout=None):
        self._push_watchers[event_type].add(callback)
        self.wait_for_response(
            protocol.RegisterMessage(event_list=[event_type]),
            timeout=register_timeout)

    def register_watchers(self, type_callback_dict, register_timeout=None):
        for event_type, callback in type_callback_dict.items():
            self._push_watchers[event_type].add(callback)
        self.wait_for_response(
            protocol.RegisterMessage(event_list=type_callback_dict.keys()),
            timeout=register_timeout)
