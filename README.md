# Event collector

This service acts as the mouth of the event pipeline. Nom nom nom.

Writing a client for this service? Check out the [API specification](https://github.com/reddit/event-collector/wiki).

On linux, you'll need to tune the SysV IPC limits:

```shell
echo 'kernel.msgmax=1000000' >> /etc/sysctl.conf # maximum number of bytes per message
echo 'kernel.msgmnb=2000000' >> /etc/sysctl.conf # maximum total size of all messages in a queue
```
