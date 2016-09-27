# if these constants change, make sure to update the sysctls and rlimits.

# maximum size of a batch of events
MAXIMUM_BATCH_SIZE = 500 * 1024

# maximum size of a single event
MAXIMUM_EVENT_SIZE = 100 * 1024

# maximum size of a message in a given queue
MAXIMUM_MESSAGE_SIZE = {
    "events": MAXIMUM_EVENT_SIZE,
    "errors": MAXIMUM_BATCH_SIZE,
}

# maximum length (in message count) of a given queue
MAXIMUM_QUEUE_LENGTH = {
    "events": 65536,
    "errors": 1024,
}
