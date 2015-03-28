import sysv_ipc


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


def make_queue(name, settings):
    """Create a queue object for the specified topic name."""

    raw_key = settings["msgq." + name]
    key = int(raw_key, 16)
    return SysVMessageQueue(key=key)
