#!/bin/bash

BOOTIMG=${1:-/dev/disk/by-partlabel/boot}
DT_ROOT=`dirname $0`/../..
DBOOTIMG=`which dbootimg`
DBOOTIMG=${DBOOTIMG:-${DT_ROOT}/tools/dbootimg/dbootimg}
DTBTOOL=`which dtbtool`
DTBTOOL=${DTBTOOL:-${DT_ROOT}/tools/dtbtool/dtbtool}
OVERLAY=`dirname $0`/overlays/db820c-spidev.dtbo

${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -m ${OVERLAY} | ${DBOOTIMG} ${BOOTIMG} -u dtb

if [ "$?" -ne 0 ]; then
	echo "Failed to update DTB"
	exit 1
fi

echo "spidev enabled, please reboot"
sync
