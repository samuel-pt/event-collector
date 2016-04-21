"""Backend process that consumes from a message queue and writes to Kafka."""
import itertools
import logging
import logging.config
import os
import time

import baseplate
import paste.deploy.loadwsgi
from baseplate.message_queue import MessageQueue

from kafka import KafkaProducer
from kafka.common import KafkaError, KafkaTimeoutError

from .const import MAXIMUM_QUEUE_LENGTH, MAXIMUM_MESSAGE_SIZE


_LOG = logging.getLogger(__name__)
_RETRY_DELAY_SECS = 1


def process_queue(queue, topic_name, kafka_producer, success_cb, err_cb,
                  metrics_client=None):
    """ Take messages off a queue and send to Kafka topic."""
    while True:
        message = queue.get()
        while True:
            try:
                kafka_producer.send(topic_name, message) \
                              .add_callback(success_cb) \
                              .add_errback(err_cb(message, queue))
            except KafkaTimeoutError:
                # In the event of a kafka error in send attempt,
                #   retry sending after a delay
                if metrics_client:
                    metrics_client.counter("injector.pre_send_error").increment()
                time.sleep(_RETRY_DELAY_SECS)
            else:
                break

def main():
    """Run a consumer.

    Two environment variables are expected:

    * CONFIG_URI: A PasteDeploy URI pointing at the configuration for the
      application.
    * QUEUE: The name of the queue to consume (currently one of "events" or
      "errors").

    """
    config_uri = os.environ["CONFIG_URI"]
    config = paste.deploy.loadwsgi.appconfig(config_uri)

    logging.config.fileConfig(config["__file__"])

    queue_name = os.environ["QUEUE"]
    queue = MessageQueue(
        "/" + queue_name,
        max_messages=MAXIMUM_QUEUE_LENGTH[queue_name],
        max_message_size=MAXIMUM_MESSAGE_SIZE[queue_name],
    )

    metrics_client = baseplate.make_metrics_client(config)

    topic_name = config["topic." + queue_name]

    # Details at http://kafka-python.readthedocs.org/en/1.0.2/apidoc/KafkaProducer.html
    producer_options = {
        "compression_type": 'gzip',
        "batch_size": 20,
        "linger_ms": 10,
        "retries": int(config["kafka_retries"]),
        "retry_backoff_ms": _RETRY_DELAY_SECS * 1000
    }

    def producer_error_cb(msg, queue):
        def requeue_msg(exc):
            _LOG.warning("failed to send message=%s due to error=%s", msg, exc)
            metrics_client.counter("injector.error").increment()
            queue.put(msg)
        return requeue_msg

    def producer_success_cb(success_val):
        metrics_client.counter("collected.injector").increment()

    while True:
        try:
            kafka_brokers = [broker.strip() for broker in config['kafka_brokers'].split(',')]
            kafka_producer = KafkaProducer(bootstrap_servers=kafka_brokers,
                                           **producer_options)
        except KafkaError as exc:
            _LOG.warning("could not connect: %s", exc)
            metrics_client.counter("injector.connection_error").increment()
            time.sleep(_RETRY_DELAY_SECS)
            continue

        process_queue(queue,
                      topic_name,
                      kafka_producer,
                      producer_success_cb,
                      producer_error_cb,
                      metrics_client=metrics_client)

        kafka_producer.stop()

if __name__ == "__main__":
    main()
