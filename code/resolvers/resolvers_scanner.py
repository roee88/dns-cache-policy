__author__ = 'Roee'

from time import time as clock
from bisect import insort
from select import select
from threading import Event

from dns_facilities import *


class ResolversScanner:
    def __init__(self, items_iter, generate_query, max_pending=500, timeout=5,
                 response_received=lambda x: None, response_timeout=lambda x: None,
                 enable_pending=True):

        self.max_pending = max_pending
        self.timeout = timeout
        self.enable_pending = enable_pending

        self.items_iter = items_iter
        self.generate_query = generate_query
        self.response_received = response_received
        self.response_timeout = response_timeout

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.socket.setblocking(False)

        self.finished = Event()

    def set_source_port(self, source_port):
        if source_port is not None:
            self.socket.bind(('0.0.0.0', source_port))

    def run(self):

        limit = float(self.timeout)/self.max_pending - 0.00267

        last_sent = clock() - limit
        s = self.socket
        it = self.items_iter
        enable_pending = self.enable_pending

        received = 0
        written = 0
        failed = 0

        try:
            # Work as long as there are more resolvers to query
            pending = []
            completed_sending = False
            while not completed_sending or pending:

                # Can I send more requests
                want_to_write = False
                if not completed_sending and len(pending) < self.max_pending:
                    want_to_write = True

                # Calculate nearest timeout time to make sure select returns on time
                timeout = None
                if pending:
                    timeout = self.timeout - clock() + pending[0][0] + 0.001
                    timeout = max(timeout, 0)

                # Up-link rate limit
                time_passed_since_send = clock() - last_sent
                if want_to_write:
                    if time_passed_since_send + 0.001 < limit:
                        timeout = min(timeout, limit-time_passed_since_send)
                        timeout = max(timeout, 0)
                        want_to_write = False
                    # print "time_passed_since_send", time_passed_since_send, timeout

                # Poll socket
                # print "timeout", timeout
                # now = clock()
                readable, writable, has_err = self._select(readable=True, writable=want_to_write, timeout=timeout)
                # print clock()-now, readable, writable, has_err

                # Error found!
                if has_err:
                    print("has error!!")
                    return

                # Can read
                if readable:
                    # Read as many as possible
                    while True:
                        try:
                            # Get response
                            response, from_address = DnsFacilities.read_response(s)

                            # Check if not duplicate or already timeout-ed
                            if enable_pending:
                                sent_time = None
                                for i, (t, ip) in enumerate(pending):
                                    if ip == from_address[0]:
                                        sent_time = t
                                        del pending[i]
                                        break

                                received += 1
                                if received % 100 == 0:
                                    print "received", received, clock()

                                if sent_time is not None:
                                    self.response_received((response, from_address, clock()-sent_time))
                            else:
                                self.response_received((response, from_address, 0))
                            # else:
                            #     print "not really pending", from_address

                        except socket.error, e:
                            if e[0] in (socket.errno.EWOULDBLOCK, socket.errno.EAGAIN):
                                break
                            elif e[0] in (socket.errno.WSAECONNRESET, socket.errno.WSAENETRESET):
                                failed += 1
                                if failed % 1000 == 0:
                                    print "failed", failed, clock()
                                pass
                            else:
                                raise

                # Can write
                if writable:
                    try:
                        # elpased = clock() - last_sent
                        # if elpased > 0.0175:
                        #     print elpased
                        last_sent = clock()

                        item = it.next()
                        query, dest = self.generate_query(item)
                        DnsFacilities.send_query(s, query, dest)
                        insort(pending, (clock(), item))

                        written += 1
                        # if written % 1000 == 0:
                        #     print "sent", written, clock()

                    except StopIteration:
                        completed_sending = True

                # Check for timeout-ed tasks
                now = clock()
                while pending and now - pending[0][0] > self.timeout:
                    if enable_pending:
                        self.response_timeout(pending[0][1])
                    del pending[0]

        finally:
            s.close()
            self.finished.set()
            print "received", received, "written", written, "failed", failed

    def is_finished(self):
        return self.finished.isSet()

    def wait_until_finished(self):
        self.finished.wait()

    def _select(self, readable=False, writable=False, err=True, timeout=None):
        fd = self.socket

        rset, wset, xset = [], [], []
        if readable:
            rset = [fd]
        if writable:
            wset = [fd]
        if err:
            xset = [fd]

        if timeout is None:
            (rcount, wcount, xcount) = select(rset, wset, xset)
        else:
            (rcount, wcount, xcount) = select(rset, wset, xset, timeout)

        return bool(rcount), bool(wcount), bool(xcount)
