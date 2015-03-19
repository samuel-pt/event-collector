import json
import unittest

import webtest

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

    def put(self, event):
        self.events.append(event)


class CollectorUnitTests(unittest.TestCase):
    def setUp(self):
        keystore = {
            "TestKey1": "test",
        }
        self.sink = MockSink()
        self.collector = collector.EventCollector(keystore, self.sink)

    def test_simple_batch(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(request.body), self.sink.events)

    def test_max_length_enforced(self):
        request = testing.DummyRequest()
        request.content_length = 50 * 1024
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.sink.events, [{"error": "TOO_BIG"}])

    def test_invalid_json(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=f8d929da113ab741eb173359f2bf28074f0ede5a2565a86389c35dd2c7ff7f6c"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.body = '!!!'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEquals(self.sink.events, [{"error": "INVALID_PAYLOAD"}])

    def test_not_a_batch(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=605cd49ebbc548885607c419e7aaafd1f97fd59c59cc099c8437fcd974c61705"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.body = '{"event1": "value"}'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.sink.events, [{"error": "INVALID_PAYLOAD"}])

    def test_no_auth(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.body = '{"event1": "value"}'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.sink.events, [{"error": "INVALID_MAC"}])

    def test_unknown_key(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["X-Signature"] = "key=UnknownKey, mac=605cd49ebbc548885607c419e7aaafd1f97fd59c59cc099c8437fcd974c61705"
        response = self.collector.process_request(request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.sink.events, [{"error": "INVALID_MAC"}])

    def test_invalid_mac(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.headers["X-Signature"] = "key=TestKey1, mac=INVALID"
        request.body = '!!!'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 403)
        self.assertEqual(self.sink.events, [{"error": "INVALID_MAC"}])

    def test_date_not_provided(self):
        request = testing.DummyRequest()
        request.headers["User-Agent"] = "TestApp/1.0"
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEqual(self.sink.events, [{"error": "NO_DATE"}])

    def test_useragent_not_provided(self):
        request = testing.DummyRequest()
        request.headers["X-Signature"] = "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed"
        request.headers["Date"] = "Wed, 25 Nov 2015 06:25:24 GMT"
        request.body = '[{"event1": "value"}, {"event2": "value"}]'
        request.content_length = len(request.body)
        response = self.collector.process_request(request)
        self.assertEquals(response.status_code, 400)
        self.assertEqual(self.sink.events, [{"error": "NO_USERAGENT"}])


class CollectorFunctionalTests(unittest.TestCase):
    def setUp(self):
        app = collector.make_app(global_config={}, **{
            "key.TestKey1": "dGVzdA==",
        })
        self.test_app = webtest.TestApp(app)

    def test_batch(self):
        self.test_app.post("/v1",
            '[{"event1": "value"}, {"event2": "value"}]',
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TestApp/1.0",
                "Date": "Wed, 25 Nov 2015 06:25:24 GMT",
                "X-Signature": "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed",
            },
        )
