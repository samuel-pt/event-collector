"""Backend process that consumes from a message queue and writes to Kafka."""
import itertools
import logging
import logging.config
import os
import time

import baseplate
import paste.deploy.loadwsgi
from baseplate.message_queue import MessageQueue

from kafka import KafkaClient, SimpleProducer
from kafka.common import KafkaError
from kafka.protocol import CODEC_GZIP

from .const import MAXIMUM_QUEUE_LENGTH, MAXIMUM_EVENT_SIZE


_LOG = logging.getLogger(__name__)
_RETRY_DELAY = 1


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
    queue = MessageQueue("/" + queue_name,
        max_messages=MAXIMUM_QUEUE_LENGTH, max_message_size=MAXIMUM_EVENT_SIZE)

    metrics_client = baseplate.make_metrics_client(config)

    topic_name = config["topic." + queue_name]

    producer_options = {
        "codec": CODEC_GZIP,
        "batch_send_every_n": 20,
        "batch_send_every_t": 0.01,  # 10 milliseconds
    }

    while True:
        try:
            kafka_client = KafkaClient(config["kafka_brokers"])
            kafka_producer = SimpleProducer(kafka_client, **producer_options)
        except KafkaError as exc:
            _LOG.warning("could not connect: %s", exc)
            metrics_client.counter("injector.connection_error").increment()
            time.sleep(_RETRY_DELAY)
            continue

        while True:
            message = queue.get()
            for retry in itertools.count():
                try:
                    kafka_producer.send_messages(topic_name, message)
                except KafkaError as exc:
                    _LOG.warning("failed to send message: %s", exc)
                    metrics_client.counter("injector.error").increment()
                    time.sleep(_RETRY_DELAY)
                else:
                    metrics_client.counter("collected.injector").increment()
                    break
        kafka_producer.stop()


if __name__ == "__main__":
    main()
