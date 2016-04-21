import unittest

import baseplate
from baseplate.message_queue import MessageQueue

from events.injector import process_queue
from kafka import KafkaProducer
from kafka.common import KafkaError
from kafka.future import Future
import mock
from mock import Mock, MagicMock



class SuccessException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class FailureException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class InjectorTests(unittest.TestCase):
    def setUp(self):
        self.event_queue = mock.create_autospec(MessageQueue)
        self.event_queue.get = Mock(side_effect=[1,2,3])
        self.mock_metrics_client = mock.create_autospec(
            baseplate.metrics.Client)
        self.allowed_origins = []
        self.kafka_producer = mock.create_autospec(KafkaProducer)

    def success_cb(self, val):
        raise SuccessException()

    def error_cb(self, message, queue):
        def raise_exception(exc):
            raise exc
        return raise_exception

    def test_process_queue(self):
        """ Verify message queue is processed."""
        mock_future = Future()
        mock_future.is_done = True
        mock_future.value = 1
        self.kafka_producer.send = MagicMock(return_value=mock_future)
        with self.assertRaises(SuccessException) as context:
            process_queue(self.event_queue,
                          "test",
                          self.kafka_producer,
                          self.success_cb,
                          self.error_cb)
        # Verify message queue "get" is called
        self.event_queue.get.assert_called_with()

    def test_process_queue_error_cb(self):
        """ Verify error callback executed on Future exception"""
        mock_future = Future()
        mock_future.is_done = True
        mock_future.exception = FailureException()
        cb_spy = Mock(wraps=self.error_cb)
        with self.assertRaises(FailureException) as context:
            self.kafka_producer.send = MagicMock(return_value=mock_future)
            process_queue(self.event_queue,
                          "test",
                          self.kafka_producer,
                          self.success_cb,
                          cb_spy)
        # Also verify propagation of queue and message to error callback.
        # Message is specified by mocking of self.event_queue.get in setUp.
        cb_spy.assert_called_with(1, self.event_queue)

    def test_process_queue_success_cb(self):
        """ Verify success callback executed on Future success"""
        mock_future = Future()
        mock_future.is_done = True
        mock_future.value = 1
        self.kafka_producer.send = MagicMock(return_value=mock_future)

        with self.assertRaises(SuccessException) as context:
            process_queue(self.event_queue,
                          "test",
                          self.kafka_producer,
                          self.success_cb,
                          self.error_cb)
