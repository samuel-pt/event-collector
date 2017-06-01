from cStringIO import StringIO
import datetime
import gzip
import unittest

import baseplate
from pyramid import testing

from events import collector


class SignatureTests(unittest.TestCase):
    def test_empty(self):
        key, mac = collector.parse_signature("")
        self.assertIsNone(key)
        self.assertIsNone(mac)

    def test_signature(self):
        key, mac = collector.parse_signature("key=MyKey, mac=AHash")
        self.assertEquals(key, "MyKey")
        self.assertEquals(mac, "AHash")

    def test_key_missing(self):
        key, mac = collector.parse_signature("mac=test")
        self.assertIsNone(key)

    def test_mac_missing(self):
        key, mac = collector.parse_signature("key=MyKey")
        self.assertIsNone(mac)


class MockSink(object):
    def __init__(self):
        self.events = []

    def put(self, event, timeout=None):
        self.events.append(event)


class MockMetricsTransport(baseplate.metrics.Transport):
    def __init__(self):
        self.metrics = []

    def send(self, metric):
        self.metrics.append(metric)

    def assert_counter_with_value(self, key, value):
        expected = "{}:{:g}|c".format(key, value)
        assert any(metric.startswith(expected) for metric in self.metrics), \
            "no metric named `{}` with value `{}` found in {!r}".format(
            key, value, self.metrics)


class CollectorUnitTests(unittest.TestCase):
    def setUp(self):
        class MockDatetime(datetime.datetime):
            @classmethod
            def utcnow(cls):
                return datetime.datetime(2015, 11, 17, 12, 34, 56)
        datetime.datetime = MockDatetime

        keystore = {
            "TestKey1": "test",
        }
        self.event_sink = MockSink()
        self.error_sink = MockSink()

        self.metrics = MockMetricsTransport()
        metrics_client = baseplate.metrics.Client(self.metrics, "collector")

        self.allowed_origins = []
        self.collector = collector.EventCollector(
            keystore,
            metrics_client,
            self.event_sink,
            self.error_sink,
            self.allowed_origins,
        )

    def test_simple_batch(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [
                '{"event1": "value"}',
                '{"event2": "value"}',
            ],
            self.event_sink.events)
        self.assertEqual(self.error_sink.events, [])
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), None)
        self.metrics.assert_counter_with_value(
            "collector.collected.http.TestKey1", 2)

    def test_gzip_batch(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"

        # Gzip
        request.headers["Content-Encoding"] = "gzip"
        f = StringIO()
        gzip.GzipFile(fileobj=f, mode='wb').write(
            '[{"event1": "value"}, {"event2": "value"}]')
        f.seek(0)
        gzipped_body = f.read()

        request.body = gzipped_body
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [
                '{"event1": "value"}',
                '{"event2": "value"}',
            ],
            self.event_sink.events)
        self.assertEqual(self.error_sink.events, [])
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), None)

    def test_max_length_enforced(self):
        request = testing.DummyRequest()
        request.headers["X-Signature"] = "key=TestKey1, mac=f8d929da113ab741eb173359f2bf28074f0ede5a2565a86389c35dd2c7ff7f6c"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.content_length = 500 * 1024 + 1
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.TOO_BIG", 1)

    def test_invalid_json(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=f8d929da113ab741eb173359f2bf28074f0ede5a2565a86389c35dd2c7ff7f6c"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '!!!'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.INVALID_PAYLOAD", 1)

    def test_bad_utf8(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=7010e4f03d53cc16f76f4818bf3de8ec50e589d38622ec06024eb0c33e92ddff"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '{"blah": "\x8b"}'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.INVALID_PAYLOAD", 1)

    def test_not_a_batch(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=605cd49ebbc548885607c419e7aaafd1f97fd59c59cc099c8437fcd974c61705"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '{"event1": "value"}'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.INVALID_PAYLOAD", 1)

    def test_no_auth(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '{"event1": "value"}'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.UNKNOWN.INVALID_MAC", 1)

    def test_unknown_key(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["X-Signature"] = "key=UnknownKey, mac=605cd49ebbc548885607c419e7aaafd1f97fd59c59cc099c8437fcd974c61705"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.UNKNOWN.INVALID_MAC", 1)

    def test_invalid_mac(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["X-Signature"] = "key=TestKey1, mac=INVALID"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '!!!'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 403)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.INVALID_MAC", 1)

    def test_date_not_provided(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 200)
        self.assertEqual(len(self.event_sink.events), 2)
        self.assertEqual(len(self.error_sink.events), 0)

    def test_useragent_not_provided(self):
        request = testing.DummyRequest()
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)

    def test_event_too_large(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=4b807bc6545bb393bc6fbe36db7c927da024b185cb8bd7a71131225ed19f8b16"
        request.headers["Date"] = "Thu, 17 Nov 2011 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "' + ("v" * 1000 * 1024) + '"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 413)
        self.assertEqual(len(self.event_sink.events), 0)
        self.assertEqual(len(self.error_sink.events), 1)
        self.metrics.assert_counter_with_value(
            "collector.client-error.TestKey1.TOO_BIG", 1)

    def test_key_in_urlparams(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.GET["key"] = "TestKey1"
        request.GET["mac"] = "d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [
                '{"event1": "value"}',
                '{"event2": "value"}',
            ],
            self.event_sink.events)
        self.assertEqual(self.error_sink.events, [])

    def test_cors_if_open(self):
        self.allowed_origins.append("*")

        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["Origin"] = "https://www.example.com"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")

    def test_cors_if_authorized(self):
        self.allowed_origins.append("example.com")

        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["Origin"] = "https://www.example.com"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")

    def test_no_cors_if_unauthorized(self):
        self.allowed_origins.append("example.com")

        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["Origin"] = "https://notexample.com"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), None)

    def test_text_plain(self):
        # we need text/plain to work, even though it's gross and icky here, so
        # that we can avoid a CORS preflight
        self.allowed_origins.append("example.com")

        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["Origin"] = "https://www.example.com"
        request.headers["Content-Type"] = "text/plain"
        request.environ["REMOTE_ADDR"] = "1.2.3.4"
        request.client_addr = "2.3.4.5"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")
