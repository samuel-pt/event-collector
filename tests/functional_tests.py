import datetime
import unittest

from baseplate.message_queue import MessageQueue, TimedOutError
import webtest

from events import collector


class CollectorFunctionalTests(unittest.TestCase):
    def setUp(self):
        # we create the queues before the actual code can so that we can
        # override the max sizes to use these numbers which are safe to use
        # without extra privileges on linux
        self.events_queue = MessageQueue(name="/events",
            max_messages=10, max_message_size=8192)
        self.errors_queue = MessageQueue(name="/errors",
            max_messages=10, max_message_size=8192)

        class MockDatetime(datetime.datetime):
            @classmethod
            def utcnow(cls):
                return datetime.datetime(2015, 11, 17, 12, 34, 56)
        datetime.datetime = MockDatetime

        app = collector.make_app(global_config={}, **{
            "key.TestKey1": "dGVzdA==",
            "msgq.events": "0xcafe",
            "msgq.errors": "0xdecaf",
            "allowed_origins": "example.com",
            "metrics.namespace": "eventcollector",
            "metrics.endpoint": "",
        })
        self.test_app = webtest.TestApp(app)

    def tearDown(self):
        self.events_queue.queue.unlink()
        self.events_queue.queue.close()
        self.errors_queue.queue.unlink()
        self.errors_queue.queue.close()

    def test_batch(self):
        self.test_app.post("/v1",
            '[{"event1": "value"}, {"event2": "value"}]',
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TestApp/1.0",
                "Date": "Wed, 25 Nov 2015 06:25:24 GMT",
                "X-Signature": "key=TestKey1, mac=d7aab40b9db8ae0e0b40d98e9c50b2cfc80ca06127b42fbbbdf146752b47a5ed",
            },
            extra_environ={
                "REMOTE_ADDR": "1.2.3.4",
            },
        )

        event1 = self.events_queue.get(timeout=0)
        self.assertEqual(event1, '{"ip": "1.2.3.4", "event": {"event1": "value"}, "time": "2015-11-17T12:34:56"}')
        event2 = self.events_queue.get(timeout=0)
        self.assertEqual(event2, '{"ip": "1.2.3.4", "event": {"event2": "value"}, "time": "2015-11-17T12:34:56"}')

        with self.assertRaises(TimedOutError):
            self.errors_queue.get(timeout=0)

    def test_cors(self):
        response = self.test_app.options("/v1", headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Signature",
        })

        self.assertEqual(response.status_code, 204)
