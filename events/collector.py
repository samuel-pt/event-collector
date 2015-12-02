"""HTTP Frontend for the event collector service."""

import base64
import datetime
import json
import hashlib
import hmac
import logging
import urlparse

from pyramid.config import Configurator
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPRequestEntityTooLarge,
)
from pyramid.response import Response

from events import stats, queue


_MAXIMUM_CONTENT_LENGTH = 40 * 1024
_MAXIMUM_EVENT_SIZE = 5120  # extra padding over spec for our wrapper
_LOG = logging.getLogger(__name__)
_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Max-Age": "1728000",  # 20 days
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "X-Signature",
    "Vary": "Origin",
}


def is_subdomain(domain, base_domain):
    """Return whether or not domain is a subdomain of base_domain."""
    return domain == base_domain or domain.endswith("." + base_domain)


def is_allowed_origin(origin, whitelist):
    """Check if the reported origin of a request is on a given whitelist."""
    # if there's no whitelist, assume all is ok
    if whitelist == ["*"]:
        return True

    try:
        parsed = urlparse.urlparse(origin)
    except ValueError:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    if parsed.port is not None and parsed.port not in (80, 443):
        return False

    for domain in whitelist:
        if is_subdomain(parsed.hostname, domain):
            return True
    return False


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


def wrap_and_serialize_event(request, event):
    """Wrap the client-sent event with some additional fields and serialize."""
    return json.dumps({
        "ip": request.environ["REMOTE_ADDR"],
        "time": request.environ["events.start_time"].isoformat(),
        "event": event,
    })


def make_error_event(request, code):
    """Create a serialized event representing a request error."""
    return wrap_and_serialize_event(request, {"error": code})


class EventCollector(object):
    """The event collector.

    It has two dependencies:

    * keystore: a mapping of key names to secret tokens.
    * queue: an object that consumes events.

    """

    def __init__(self, keystore, stats_client, event_queue, error_queue, allowed_origins):
        self.keystore = keystore
        self.stats_client = stats_client
        self.event_queue = event_queue
        self.error_queue = error_queue
        self.allowed_origins = allowed_origins

    def check_cors(self, request):
        try:
            origin = request.headers["Origin"]
            requested_method = request.headers["Access-Control-Request-Method"]
        except KeyError:
            self.stats_client.count("cors.preflight.missing_headers")
            raise HTTPForbidden()

        headers_list = request.headers.get("Access-Control-Request-Headers", "")
        requested_headers = [h.strip().lower() for h in headers_list.split(",") if h]
        if requested_headers and requested_headers != ["x-signature"]:
            self.stats_client.count("cors.preflight.bad_requested_headers")
            raise HTTPForbidden()

        if requested_method != "POST":
            self.stats_client.count("cors.preflight.bad_method")
            raise HTTPForbidden()

        if not origin or not is_allowed_origin(origin, self.allowed_origins):
            self.stats_client.count("cors.preflight.bad_origin")
            raise HTTPForbidden()

        self.stats_client.count("cors.preflight.allowed")
        return Response(
            status="204 No Content",
            headers=_CORS_HEADERS,
        )

    def process_request(self, request):
        """Consume an event batch request and return an appropriate response.

        The API spec:

            * the payload is a JSON list of objects, each object being an event
            * batches are at most 40 KiB in size
            * messages are signed with HMAC SHA-256

        If the payload is valid, the events it contains will be put onto the
        event queue.  If there are issues with the request, error events will be
        put into the error queue instead.

        """

        request.environ["events.start_time"] = datetime.datetime.utcnow()

        if request.content_length > _MAXIMUM_CONTENT_LENGTH:
            self.stats_client.count("client-error.too-big")
            error = make_error_event(request, "TOO_BIG")
            self.error_queue.put(error)
            return HTTPRequestEntityTooLarge()

        if not request.headers.get("User-Agent"):
            self.stats_client.count("client-error.no-useragent")
            error = make_error_event(request, "NO_USERAGENT")
            self.error_queue.put(error)
            return HTTPBadRequest("no user-agent provided")

        try:
            signature_header = request.headers["X-Signature"]
        except KeyError:
            keyname = request.GET.get("key", "")
            mac = request.GET.get("mac", "")
        else:
            keyname, mac = parse_signature(signature_header)

        key = self.keystore.get(keyname, "INVALID")
        body = request.body
        expected_mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        if not constant_time_compare(expected_mac, mac or ""):
            self.stats_client.count("client-error.invalid-mac")
            error = make_error_event(request, "INVALID_MAC")
            self.error_queue.put(error)
            return HTTPForbidden()

        try:
            batch = json.loads(body)
        except ValueError:
            self.stats_client.count("client-error.invalid-payload")
            error = make_error_event(request, "INVALID_PAYLOAD")
            self.error_queue.put(error)
            return HTTPBadRequest("invalid json")

        if not isinstance(batch, list):
            self.stats_client.count("client-error.invalid-payload")
            error = make_error_event(request, "INVALID_PAYLOAD")
            self.error_queue.put(error)
            return HTTPBadRequest("json root object must be a list")

        reserialized_items = []
        for item in batch:
            reserialized = wrap_and_serialize_event(request, item)
            if len(reserialized) > _MAXIMUM_EVENT_SIZE:
                self.stats_client.count("client-error.too-big")
                error = make_error_event(request, "EVENT_TOO_BIG")
                self.error_queue.put(error)
                return HTTPRequestEntityTooLarge()
            reserialized_items.append(reserialized)

        for item in reserialized_items:
            self.event_queue.put(item)

        self.stats_client.count("collected.http", count=len(reserialized_items))

        headers = {}
        origin = request.headers.get("Origin")
        if origin and is_allowed_origin(origin, self.allowed_origins):
            headers.update(_CORS_HEADERS)

        return Response(headers=headers)


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

    allowed_origins = [
        x.strip() for x in settings["allowed_origins"].split(",") if x.strip()]

    stats_client = stats.make_stats_client(settings)
    event_queue = queue.make_queue("events", settings)
    error_queue = queue.make_queue("errors", settings)
    collector = EventCollector(
        keystore, stats_client, event_queue, error_queue, allowed_origins)
    config.add_route("v1", "/v1", request_method="POST")
    config.add_route("v1_options", "/v1", request_method="OPTIONS")
    config.add_view(collector.process_request, route_name="v1")
    config.add_view(collector.check_cors, route_name="v1_options")
    config.add_route("health", "/health")
    config.add_view(health_check, route_name="health", renderer="json")

    return config.make_wsgi_app()
