#!/bin/sh
# The vendor calls this when the backhaul moves. Limit the flush to dynamic
# entries on the LAN bridge; do not touch switch-wide or static forwarding.
[ "$#" -eq 2 ] || exit 1
case "$1:$2" in
  0:0) exit 0 ;;
  0:1|1:0|1:1) exec /usr/libexec/ip-full link set dev br-lan type bridge fdb_flush ;;
  *) exit 1 ;;
esac
