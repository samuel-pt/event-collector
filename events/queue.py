import time

import sysv_ipc


# how long to sleep when no items are in the message queue (seconds)
BUSY_WAIT = 0.05


class QueueFullError(Exception):
    """The sink is full.

    It may have space again in the future, but at the moment writes are not
    allowed.

    """
    pass


class SysVMessageQueue(object):
    """A queue using System V IPC Message Queues.

    Note: system-level tuning is required for this to work; the expected
    maximum message size is larger than most system defaults. See your OS's
    man pages for more information.

    """
    def __init__(self, key):
        self.queue = sysv_ipc.MessageQueue(
            key=key,
            flags=sysv_ipc.IPC_CREAT,
            mode=0600,
            max_message_size=5120
        )

    def put(self, event):
        """Put an item on the queue or raise QueueFullError."""
        try:
            self.queue.send(event, block=False)
        except sysv_ipc.BusyError as e:
            raise QueueFullError(e)

    def consume(self):
        """Consume messages from the message queue and return them.

        If no messages are available, this will sleep BUSY_WAIT seconds and
        return None.

        """
        while True:
            try:
                message, _ = self.queue.receive(block=False)
            except sysv_ipc.BusyError:
                time.sleep(BUSY_WAIT)
                yield None
            else:
                yield message


def make_queue(name, settings):
    """Create a queue object for the specified topic name."""

    raw_key = settings["msgq." + name]
    key = int(raw_key, 16)
    return SysVMessageQueue(key=key)
