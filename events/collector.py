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
_MAXIMUM_EVENT_SIZE = 4096
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


def make_error_event(request, code):
    """Create an event representing a request error."""
    return {"error": code}


class EventCollector(object):
    """The event collector.

    It has two dependencies:

    * keystore: a mapping of key names to secret tokens.
    * sink: an object that consumes events.

    """

    def __init__(self, keystore, event_sink, error_sink):
        self.keystore = keystore
        self.event_sink = event_sink
        self.error_sink = error_sink

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
            error = make_error_event(request, "TOO_BIG")
            self.error_sink.put(error)
            return HTTPRequestEntityTooLarge()

        if not request.headers.get("Date"):
            error = make_error_event(request, "NO_DATE")
            self.error_sink.put(error)
            return HTTPBadRequest("no date provided")

        if not request.headers.get("User-Agent"):
            error = make_error_event(request, "NO_USERAGENT")
            self.error_sink.put(error)
            return HTTPBadRequest("no user-agent provided")

        signature_header = request.headers.get("X-Signature", "")
        keyname, mac = parse_signature(signature_header)
        key = self.keystore.get(keyname, "INVALID")
        body = request.body
        expected_mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        if not constant_time_compare(expected_mac, mac or ""):
            error = make_error_event(request, "INVALID_MAC")
            self.error_sink.put(error)
            return HTTPForbidden()

        try:
            batch = json.loads(body)
        except ValueError:
            error = make_error_event(request, "INVALID_PAYLOAD")
            self.error_sink.put(error)
            return HTTPBadRequest("invalid json")

        if not isinstance(batch, list):
            error = make_error_event(request, "INVALID_PAYLOAD")
            self.error_sink.put(error)
            return HTTPBadRequest("json root object must be a list")

        reserialized_items = []
        for item in batch:
            reserialized = json.dumps(item)
            if len(reserialized) > _MAXIMUM_EVENT_SIZE:
                error = make_error_event(request, "EVENT_TOO_BIG")
                self.error_sink.put(error)
                return HTTPRequestEntityTooLarge()
            reserialized_items.append(reserialized)

        for item in reserialized_items:
            self.event_sink.put(item)
        return Response()


class StubSink(object):
    """A temporary stub event sink."""

    def put(self, event):
        """Put an event into the event queue."""
        _LOG.warn(event)


def health_check(request):
    """A very simple health check endpoint."""
    return {
        "mood": u"\U0001F357",
    }


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

    event_sink = StubSink()
    error_sink = StubSink()
    collector = EventCollector(keystore, event_sink, error_sink)
    config.add_route("v1", "/v1", request_method="POST")
    config.add_view(collector.process_request, route_name="v1")
    config.add_route("health", "/health")
    config.add_view(health_check, route_name="health", renderer="json")

    return config.make_wsgi_app()
