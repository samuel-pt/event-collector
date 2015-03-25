Event collection service for reddit.

https://reddit.atlassian.net/wiki/display/IS/Event+collector+API+specification

On linux, you'll need to tune the SysV IPC limits:

echo 'kernel.msgmax=1000000' >> /etc/sysctl.conf # maximum number of bytes per message
echo 'kernel.msgmnb=2000000' >> /etc/sysctl.conf # maximum total size of all messages in a queue
