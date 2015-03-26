import unittest

import mock

import events.queue


class SysVMessageQueueTests(unittest.TestCase):
    def setUp(self):
        self.queues = []

    def tearDown(self):
        for queue in self.queues:
            try:
                queue.remove()
            except:
                pass

    def _make_queue(self, key):
        queue = events.queue.SysVMessageQueue(key=key)
        self.queues.append(queue.queue)
        return queue

    def test_create_new(self):
        queue = self._make_queue(key=0x5ca1ab1e)
        self.assertEqual(queue.queue.key, 0x5ca1ab1e)

    def test_create_existing(self):
        queue1 = self._make_queue(key=0x5ca1ab1e)
        queue2 = self._make_queue(key=0x5ca1ab1e)
        self.assertEqual(queue1.queue.key, 0x5ca1ab1e)
        self.assertEqual(queue2.queue.key, 0x5ca1ab1e)

    def test_put_message(self):
        queue = self._make_queue(key=0x5ca1ab1e)
        input = "Test"
        queue.put(input)
        output, msgtype = queue.queue.receive(block=False)
        self.assertEqual(input, output)

    def test_full_queue(self):
        queue = self._make_queue(key=0x5ca1ab1e)
        with self.assertRaises(events.queue.QueueFullError):
            # we can't control the sysctl for max queue length but we can be
            # sure that if we keep throwing stuff in there it'll fill up
            # eventually
            while True:
                queue.put("Example" * 100)

    def test_consume_empty(self):
        queue = self._make_queue(key=0x5ca1ab1e)
        iterator = queue.consume()
        with mock.patch("time.sleep") as mock_sleep:
            item = iterator.next()
            self.assertTrue(mock_sleep.called)
        self.assertEqual(item, None)

    def test_consume_with_items(self):
        queue = self._make_queue(key=0x5ca1ab1e)
        queue.put("example")
        iterator = queue.consume()
        item = iterator.next()
        self.assertEqual(item, "example")
