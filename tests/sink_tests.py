import unittest

import events.sink


class SysVMessageQueueTests(unittest.TestCase):
    def setUp(self):
        self.queues = []

    def tearDown(self):
        for queue in self.queues:
            try:
                queue.remove()
            except:
                pass

    def _make_sink(self, key):
        sink = events.sink.SysVMessageQueueSink(key=key)
        self.queues.append(sink.queue)
        return sink

    def test_create_new(self):
        sink = self._make_sink(key=0x5ca1ab1e)
        self.assertEqual(sink.queue.key, 0x5ca1ab1e)

    def test_create_existing(self):
        sink1 = self._make_sink(key=0x5ca1ab1e)
        sink2 = self._make_sink(key=0x5ca1ab1e)
        self.assertEqual(sink1.queue.key, 0x5ca1ab1e)
        self.assertEqual(sink2.queue.key, 0x5ca1ab1e)

    def test_put_message(self):
        sink = self._make_sink(key=0x5ca1ab1e)
        input = "Test"
        sink.put(input)
        output, msgtype = sink.queue.receive(block=False)
        self.assertEqual(input, output)

    def test_full_queue(self):
        sink = self._make_sink(key=0x5ca1ab1e)
        with self.assertRaises(events.sink.SinkFullError):
            # we can't control the sysctl for max queue length but we can be
            # sure that if we keep throwing stuff in there it'll fill up
            # eventually
            while True:
                sink.put("Example" * 100)
