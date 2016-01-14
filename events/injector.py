"""Backend process that consumes from a message queue and writes to Kinesis."""
import itertools
import logging
import logging.config
import os
import time
import uuid

import baseplate
import boto
import boto.kinesis
import boto.kinesis.layer1
import boto.regioninfo
import paste.deploy.loadwsgi

from boto.kinesis.exceptions import ProvisionedThroughputExceededException

import events.queue


# hack in support for the US-WEST-2 region in Kinesis
original_regions = boto.kinesis.regions
def patched_regions():
    return original_regions() + [
        boto.regioninfo.RegionInfo(
            name="us-west-2",
            endpoint="kinesis.us-west-2.amazonaws.com",
            connection_cls=boto.kinesis.layer1.KinesisConnection,
        ),
    ]
boto.kinesis.regions = patched_regions


# maximum size of a single record in kinesis (bytes)
_MAX_RECORD_LEN = 1024 * 1024
# maximum delay while trying to build a larger batch (seconds)
_MAX_WAIT = 3
# exponential backoff for when exceeding provisioned throughput (seconds)
_BASE_RETRY = 2


_LOG = logging.getLogger(__name__)


class Batcher(object):
    """Time-aware batching producer.

    A batch-consumer gives necessary context to this object. It must provide:

        * batch_size_limit - the maximum size of an individual batch
        * get_item_size() - given an item, return its batch-relevant size
        * consume_batch() - consume a fully formed batch

    A flush may occur if the batch reaches the maximum specified size during
    add() or if explicitly flush()ed.

    """
    def __init__(self, consumer):
        self.consumer = consumer
        self.batch = []
        self.batch_size = 0
        self.batch_start = None

    @property
    def batch_age(self):
        """Return the age in seconds of the oldest item in the batch.

        If there are no items in the batch, 0 is returned.

        """
        if not self.batch_start:
            return 0
        return time.time() - self.batch_start

    def add(self, item):
        """Add an item to the batch, potentially flushing."""
        item_size = self.consumer.get_item_size(item)
        if self.batch_size + item_size > self.consumer.batch_size_limit:
            self.flush()
        self.batch.append(item)
        self.batch_size += item_size
        if not self.batch_start:
            self.batch_start = time.time()

    def flush(self):
        """Explicitly flush the batch if any items are enqueued."""
        if self.batch:
            self.consumer.consume_batch(self.batch)
            self.batch = []
            self.batch_size = 0
            self.batch_start = None


class KinesisBatchConsumer(object):
    """An AWS Kinesis batch consumer for use with Batcher."""
    batch_size_limit = _MAX_RECORD_LEN

    def __init__(self, kinesis, topic, metrics_client):
        self.kinesis = kinesis
        self.topic = topic
        self.metrics_client = metrics_client

    @staticmethod
    def get_item_size(item):
        """Return the size of an item.

        We add one to its length to account for the delimiting newline in
        batches.

        """
        return len(item) + 1

    def consume_batch(self, items):
        """Serialize and send a batch of records to Kinesis.

        Rather than using put_records(), we're using put_record() with a
        manually created batch of newline-separated events.  Since our events
        are small, this allows us to more effectively use the 1,000 records per
        second limit of each Kinesis shard.

        The partition key is just a random UUID.

        """
        _LOG.info("flushing %d items", len(items))
        partition_key = str(uuid.uuid4())
        data = "\n".join(items)

        for retry in itertools.count():
            try:
                self.kinesis.put_record(self.topic, data, partition_key)
            except ProvisionedThroughputExceededException:
                _LOG.warning("throughput exceeded, backing off")
                self.metrics_client.counter(
                    "injector.throughput-exceeded").increment()
                time.sleep(_BASE_RETRY ** retry)
            else:
                self.metrics_client.counter(
                    "collected.injector").increment(len(items))
                break


def consume_items_in_batches(queue, batcher):
    """Feed items from a generator into a batcher, flushing on timeout."""
    for item in queue:
        if item:
            batcher.add(item)

        if batcher.batch_age > _MAX_WAIT:
            batcher.flush()


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
    queue = events.queue.make_queue(queue_name, config)
    messages = queue.consume()

    topic_name = config["topic." + queue_name]
    region = config["aws.region"]
    kinesis = boto.kinesis.connect_to_region(region)

    metrics_client = baseplate.make_metrics_client(config)
    kinesis_batch_consumer = KinesisBatchConsumer(
        kinesis, topic_name, metrics_client)
    batcher = Batcher(kinesis_batch_consumer)
    consume_items_in_batches(messages, batcher)


if __name__ == "__main__":
    main()
