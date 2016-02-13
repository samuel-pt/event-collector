# Event collector

This service acts as the mouth of the event pipeline. Nom nom nom.

Writing a client for this service? Check out the [API specification](https://github.com/reddit/event-collector/wiki).

On Linux, you'll need to tune the POSIX Message Queue limits:

```shell
echo 'fs.mqueue.msgsize_max = 102400' >> /etc/sysctl.conf # maximum size of an individual message, bytes
echo 'fs.mqueue.msg_max = 65536' >> /etc/sysctl.conf # maximum number of messages in a queue
```
