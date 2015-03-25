import sysv_ipc


class SinkFullError(Exception):
    """The sink is full.

    It may have space again in the future, but at the moment writes are not
    allowed.

    """
    pass


class SysVMessageQueueSink(object):
    """A sink that uses System V IPC Message Queues for communication.

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
        try:
            self.queue.send(event, block=False)
        except sysv_ipc.BusyError as e:
            raise SinkFullError(e)


def make_sink(name, settings):
    """Create a sink object for the specified topic name."""

    raw_key = settings["msgq." + name]
    key = int(raw_key, 16)
    return SysVMessageQueueSink(key=key)
