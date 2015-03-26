import unittest

import mock

from boto.kinesis.exceptions import ProvisionedThroughputExceededException

from events import injector


class BatcherTests(unittest.TestCase):
    def setUp(self):
        self.consumer = mock.MagicMock()
        self.consumer.get_item_size = lambda item: len(item)
        self.consumer.batch_size_limit = 5
        self.batcher = injector.Batcher(self.consumer)

    def test_flush_empty_does_nothing(self):
        self.batcher.flush()
        self.assertEqual(self.consumer.consume_batch.called, False)

    def test_start_time(self):
        with mock.patch("time.time") as mock_time:
            self.assertEqual(self.batcher.batch_age, 0)

            mock_time.return_value = 33
            self.batcher.add("a")
            self.assertEqual(self.batcher.batch_start, 33)

            mock_time.return_value = 34
            self.batcher.add("b")
            self.assertEqual(self.batcher.batch_start, 33)

            mock_time.return_value = 35
            self.assertEqual(self.batcher.batch_age, 2)

        self.batcher.flush()
        self.assertEqual(self.batcher.batch_start, None)

    def test_manual_flush(self):
        self.batcher.add("a")
        self.batcher.add("b")
        self.batcher.flush()
        self.consumer.consume_batch.assert_called_once_with(["a", "b"])

    def test_flush_when_full(self):
        for i in xrange(7):
            self.batcher.add(str(i))
        self.consumer.consume_batch.assert_called_once_with(
            ["0", "1", "2", "3", "4"])


class KinesisBatchConsumerTests(unittest.TestCase):
    def test_get_item_size(self):
        batch_consumer = injector.KinesisBatchConsumer(None, "topic")
        size = batch_consumer.get_item_size("test")
        self.assertEqual(size, 5)

    def test_consume(self):
        mock_kinesis = mock.MagicMock()
        batch_consumer = injector.KinesisBatchConsumer(mock_kinesis, "topic")

        with mock.patch("uuid.uuid4") as mock_uuid1:
            mock_uuid1.return_value = "not_actually_a_uuid"
            batch_consumer.consume_batch(["first", "second", "third"])

        mock_kinesis.put_record.assert_called_once_with(
            "topic", "first\nsecond\nthird", "not_actually_a_uuid")

    def test_throughput_exceeded(self):
        mock_kinesis = mock.MagicMock()
        batch_consumer = injector.KinesisBatchConsumer(mock_kinesis, "topic")

        mock_kinesis.put_record.side_effect = [
            ProvisionedThroughputExceededException(400, "too"),
            ProvisionedThroughputExceededException(400, "fast"),
            ProvisionedThroughputExceededException(400, "yikes"),
            None,
        ]

        with mock.patch("time.sleep") as mock_sleep:
            batch_consumer.consume_batch(["a", "b", "c"])
            mock_sleep.assert_has_calls([
                mock.call(1),
                mock.call(2),
                mock.call(4),
            ])


class ConsumeInBatchesTests(unittest.TestCase):
    def test_no_timeout(self):
        mock_queue = ["one", "two", "three"]
        mock_batcher = mock.MagicMock()
        mock_batcher.batch_age = 0

        injector.consume_items_in_batches(mock_queue, mock_batcher)

        self.assertEqual(mock_batcher.add.call_count, 3)
        self.assertFalse(mock_batcher.flush.called)

    def test_timeout(self):
        mock_queue = ["one"]
        mock_batcher = mock.MagicMock()
        mock_batcher.batch_age = 60

        injector.consume_items_in_batches(mock_queue, mock_batcher)
        self.assertEqual(mock_batcher.add.call_count, 1)
        self.assertTrue(mock_batcher.flush.called)
