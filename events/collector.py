"""HTTP Frontend for the event collector service."""

import base64
import json
import hashlib
import hmac
import logging

from pyramid.config import Configurator
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPRequestEntityTooLarge,
)
from pyramid.response import Response


_MAXIMUM_CONTENT_LENGTH = 40 * 1024
_LOG = logging.getLogger(__name__)


def parse_signature(header):
    """Parse an X-Signature header and return keyname and MAC.

    The header takes the form of:

        X-Signature: key=KeyName, mac=12345678abcdef

    The return value is a two-tuple of keyname and MAC, where if either are
    missing the result will be None.

    """
    pairs = [p.strip() for p in header.split(",") if p.strip()]
    params = dict(p.split("=") for p in pairs)
    return params.get("key"), params.get("mac")


def constant_time_compare(actual, expected):
    """Return if two strings are equal, taking as much time either way.

    The time taken is dependent on the number of characters provided instead
    of the number of characters that match.

    hmac.compare_digest obsoletes this when Python 2.7.7+ is available.

    """
    actual_len = len(actual)
    expected_len = len(expected)
    result = actual_len ^ expected_len
    if expected_len > 0:
        for i in xrange(actual_len):
            result |= ord(actual[i]) ^ ord(expected[i % expected_len])
    return result == 0


class EventCollector(object):
    """The event collector.

    It has two dependencies:

    * keystore: a mapping of key names to secret tokens.
    * sink: an object that consumes events.

    """

    def __init__(self, keystore, sink):
        self.keystore = keystore
        self.sink = sink

    def process_request(self, request):
        """Consume an event batch request and return an appropriate response.

        The API spec:

            * the payload is a JSON list of objects, each object being an event
            * batches are at most 40 KiB in size
            * messages are signed with HMAC SHA-256

        If the payload is valid, the events it contains will be put onto the
        event sink.  If there are issues with the request, error events will be
        put into the sink instead.

        """

        if request.content_length > _MAXIMUM_CONTENT_LENGTH:
            self.sink.put_error("TOO_BIG", request)
            return HTTPRequestEntityTooLarge()

        if not request.headers.get("Date"):
            self.sink.put_error("NO_DATE", request)
            return HTTPBadRequest("no date provided")

        if not request.headers.get("User-Agent"):
            self.sink.put_error("NO_USERAGENT", request)
            return HTTPBadRequest("no user-agent provided")

        signature_header = request.headers.get("X-Signature", "")
        keyname, mac = parse_signature(signature_header)
        key = self.keystore.get(keyname, "INVALID")
        body = request.body
        expected_mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        if not constant_time_compare(expected_mac, mac or ""):
            self.sink.put_error("INVALID_MAC", request)
            return HTTPForbidden()

        try:
            batch = json.loads(body)
        except ValueError:
            self.sink.put_error("INVALID_PAYLOAD", request)
            return HTTPBadRequest("invalid json")

        if not isinstance(batch, list):
            self.sink.put_error("INVALID_PAYLOAD", request)
            return HTTPBadRequest("json root object must be a list")

        for item in batch:
            self.sink.put(item)
        return Response()


class StubSink(object):
    """A temporary stub event sink."""

    def put(self, event):
        """Put an event into the event queue."""
        _LOG.warn(event)

    def put_error(self, error, request):
        """Make and put an error marker into the event queue."""
        _LOG.error(error)


def make_app(global_config, **settings):
    """Paste entry point: return a configured WSGI application."""

    config = Configurator(settings=settings)

    keystore = {}
    for setting, value in settings.iteritems():
        key_prefix = "key."
        if setting.startswith(key_prefix):
            key_name = setting[len(key_prefix):]
            key_secret = base64.b64decode(value)
            keystore[key_name] = key_secret

    sink = StubSink()
    collector = EventCollector(keystore, sink)
    config.add_route("v1", "/v1", request_method="POST")
    config.add_view(collector.process_request, route_name="v1")

    return config.make_wsgi_app()
