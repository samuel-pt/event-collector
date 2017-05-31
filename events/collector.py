"""HTTP Frontend for the event collector service."""

import base64
from cStringIO import StringIO
import datetime
import gzip
import json
import hashlib
import hmac
import logging
import urlparse

import baseplate
from baseplate.crypto import constant_time_compare
from baseplate.message_queue import MessageQueue, MessageQueueError
from pyramid.config import Configurator
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPRequestEntityTooLarge,
)
from pyramid.response import Response

from .const import (
    MAXIMUM_BATCH_SIZE,
    MAXIMUM_EVENT_SIZE,
    MAXIMUM_MESSAGE_SIZE,
    MAXIMUM_QUEUE_LENGTH,
)


# The log level used here is defined in /etc/events.ini
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


def wrap_and_serialize_event(request, event):
    """Wrap the client-sent event with some additional fields and serialize."""
    return json.dumps({
        "ip": request.client_addr,
        "time": request.environ["events.start_time"].isoformat(),
        "event": event,
    })


class EventCollector(object):
    """The event collector.

    It has two dependencies:

    * keystore: a mapping of key names to secret tokens.
    * queue: an object that consumes events.

    """

    def __init__(self, keystore, metrics_client, event_queue, error_queue, allowed_origins):
        self.keystore = keystore
        self.metrics_client = metrics_client
        self.event_queue = event_queue
        self.error_queue = error_queue
        self.allowed_origins = allowed_origins

    def check_cors(self, request):
        try:
            origin = request.headers["Origin"]
            requested_method = request.headers["Access-Control-Request-Method"]
        except KeyError:
            self.metrics_client.counter(
                "cors.preflight.missing_headers").increment()
            raise HTTPForbidden()

        headers_list = request.headers.get("Access-Control-Request-Headers", "")
        requested_headers = [h.strip().lower() for h in headers_list.split(",") if h]
        if requested_headers and requested_headers != ["x-signature"]:
            self.metrics_client.counter(
                "cors.preflight.bad_requested_headers").increment()
            raise HTTPForbidden()

        if requested_method != "POST":
            self.metrics_client.counter(
                "cors.preflight.bad_method").increment()
            raise HTTPForbidden()

        if not origin or not is_allowed_origin(origin, self.allowed_origins):
            self.metrics_client.counter(
                "cors.preflight.bad_origin").increment()
            raise HTTPForbidden()

        self.metrics_client.counter("cors.preflight.allowed").increment()
        return Response(
            status="204 No Content",
            headers=_CORS_HEADERS,
        )

    def _publish_error(self, request, keyname, code):
        metric_name = "client-error.{}.{}".format(keyname, code)
        self.metrics_client.counter(metric_name).increment()

        # the -100 allows some room for the wrapper
        unicode_body = request.body.decode("utf8", "replace")
        truncated_body = unicode_body[:MAXIMUM_BATCH_SIZE-100]
        error = wrap_and_serialize_event(request, {
            "key": keyname,
            "error": code,
            "raw_batch": truncated_body,
        })

        try:
            self.error_queue.put(error, timeout=0)
        except MessageQueueError as exc:
            _LOG.warning("failed to publish error: %r", exc)

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

        try:
            signature_header = request.headers["X-Signature"]
        except KeyError:
            keyname = request.GET.get("key", "")
            mac = request.GET.get("mac", "")
        else:
            keyname, mac = parse_signature(signature_header)

        try:
            key = self.keystore[keyname]
        except KeyError:
            keyname = "UNKNOWN"
            key = "INVALID"

        if request.content_length > MAXIMUM_BATCH_SIZE:
            self._publish_error(request, keyname, "TOO_BIG")
            return HTTPRequestEntityTooLarge()
        body = request.body

        if not request.headers.get("User-Agent"):
            self._publish_error(request, keyname, "NO_USERAGENT")
            return HTTPBadRequest("no user-agent provided")

        # Handle Gzipped Requests
        if request.headers.get('Content-Encoding') == 'gzip':
            f = StringIO(body)
            try:
                body = gzip.GzipFile(fileobj=f).read()
            except IOError:
                return HTTPBadRequest("invalid gzip content")

        expected_mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        _LOG.debug(
            'Received request with key: %r, mac: %r, expected_mac: %r',
            key, mac, expected_mac)
        if not constant_time_compare(expected_mac, mac or ""):
            self._publish_error(request, keyname, "INVALID_MAC")
            return HTTPForbidden()

        try:
            batch = json.loads(body)
        except ValueError:
            self._publish_error(request, keyname, "INVALID_PAYLOAD")
            return HTTPBadRequest("invalid json")

        if not isinstance(batch, list):
            self._publish_error(request, keyname, "INVALID_PAYLOAD")
            return HTTPBadRequest("json root object must be a list")

        reserialized_items = []
        for item in batch:
            if len(item) > MAXIMUM_EVENT_SIZE:
                self._publish_error(request, keyname, "EVENT_TOO_BIG")
                return HTTPRequestEntityTooLarge()
            reserialized_items.append(item)

        for item in reserialized_items:
            self.event_queue.put(item)

        self.metrics_client.counter("collected.http." + keyname).increment(
            len(reserialized_items))

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

    metrics_client = baseplate.make_metrics_client(settings)
    event_queue = MessageQueue(
        "/events",
        max_messages=MAXIMUM_QUEUE_LENGTH["events"],
        max_message_size=MAXIMUM_MESSAGE_SIZE["events"],
    )
    error_queue = MessageQueue(
        "/errors",
        max_messages=MAXIMUM_QUEUE_LENGTH["errors"],
        max_message_size=MAXIMUM_MESSAGE_SIZE["errors"],
    )
    collector = EventCollector(
        keystore, metrics_client, event_queue, error_queue, allowed_origins)
    config.add_route("v1", "/v1", request_method="POST")
    config.add_route("v1_options", "/v1", request_method="OPTIONS")
    config.add_view(collector.process_request, route_name="v1")
    config.add_view(collector.check_cors, route_name="v1_options")
    config.add_route("health", "/health")
    config.add_view(health_check, route_name="health", renderer="json")

    return config.make_wsgi_app()
