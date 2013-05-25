#!/bin/sh
### BEGIN INIT INFO
# Provides:          vhtcpd
# Required-Start:    $syslog $remote_fs
# Required-Stop:     $syslog $remote_fs
# Should-Start:      $local_fs
# Should-Stop:       $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: vhtcpd
# Description:       Varnish HTCP->PURGE proxy
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/vhtcpd
NAME="vhtcpd"

test -x $DAEMON || exit 0

. /lib/lsb/init-functions

[ -f /etc/default/$NAME ] && . /etc/default/$NAME

VHTCPD_CMD="$DAEMON $DAEMON_OPTS"

vhtcpd_cmd() {
    $VHTCPD_CMD "$1" >/dev/null 2>/dev/null
    ret=$?
    log_end_msg $ret
    exit $ret
}

case "$1" in
    start)
        log_daemon_msg "Starting $NAME" "$NAME"
        vhtcpd_cmd "$1"
        ;;
    stop)
        log_daemon_msg "Stopping $NAME" "$NAME"
        vhtcpd_cmd "$1"
        ;;
    reload|force-reload|restart|condrestart|try-restart)
        log_daemon_msg "Restarting $NAME" "$NAME"
        vhtcpd_cmd "$1"
        ;;
    status)
        vhtcpd_cmd $1 >/dev/null 2>/dev/null
        case "$?" in
            0) log_success_msg "$NAME is running"; exit 0 ;;
            *) log_failure_msg "$NAME is not running"; exit 3 ;;
        esac
        ;;
    *)
        echo "Usage: /etc/init.d/vhtcpd {start|stop|reload|force-reload|restart|condrestart|status}"
        exit 1
esac

exit 0
