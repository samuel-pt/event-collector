"""Backend process that consumes from a message queue and writes to Google PubSub."""
import itertools
import logging
import logging.config
import os
import time

import baseplate
import paste.deploy.loadwsgi
from baseplate.message_queue import MessageQueue

from google.cloud import pubsub
from google.cloud.exceptions import NotFound
from google.cloud.exceptions import GoogleCloudError
from google.gax.errors import GaxError

from .const import MAXIMUM_QUEUE_LENGTH, MAXIMUM_MESSAGE_SIZE


_LOG = logging.getLogger(__name__)
_RETRY_DELAY_SECS = 1


def process_queue(queue, ps_topic,
                  metrics_client=None):
    """ Take messages off a queue and send to Google PubSub topic."""
    while True:
        message = queue.get()
        while True:
            try:
                ps_topic.publish(message)
                if metrics_client:
                    metrics_client.counter("collected.google_injector").increment()
            except (GaxError, GoogleCloudError) as exc:
                _LOG.warning("failed to send message=%s due to error=%s", message, exc)
                # In the event of a Google PubSub error in send attempt,
                #   retry sending after a delay
                if metrics_client:
                    metrics_client.counter("google_injector.pre_send_error").increment()
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
    """
    Assumption: Config will have topic_name for the respective queue_name
    """
    topic_name = config["topic." + queue_name]

    while True:
        try:
            ps = pubsub.Client()
            ps_topic = ps.topic(topic_name)
        except NotFound as exc:
            _LOG.warning("Topic %s not found. Please create it", topic_name)
            metrics_client.counter("google_injector.connection_error").increment()
            time.sleep(_RETRY_DELAY_SECS)
            continue

        process_queue(queue,
                      ps_topic,
                      metrics_client=metrics_client)


if __name__ == "__main__":
    main()
