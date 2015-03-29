"""Client for statsd system."""
import logging
import socket


_LOG = logging.getLogger(__name__)


class StatsClient(object):
    """Client for a statsd stats system.

    The client does nothing unless connect() is called.

    """
    def __init__(self):
        self.sock = None
        self.address = None

    def connect(self, host, port):
        """Connect to a specified host and port."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = (host, port)

    def _send(self, message):
        if self.sock:
            try:
                self.sock.sendto(message, self.address)
            except socket.error as err:
                _LOG.warning("failed to send stats: %s", err)

    def count(self, key, count=1):
        """Count instances of a key."""
        self._send("eventcollector.%s:%d|c\n" % (key, count))


def make_stats_client(config):
    """Return a configured stats client."""
    client = StatsClient()
    address = config.get("stats.address")
    if address:
        host, colon, port = address.partition(":")
        if colon != ":":
            port = 8125
        client.connect(host, int(port))
    return client
