#!/bin/bash

BOOTIMG=${1:-/dev/disk/by-partlabel/boot}
DT_ROOT=`dirname $0`/../..
DBOOTIMG=`which dbootimg`
DBOOTIMG=${DBOOTIMG:-${DT_ROOT}/tools/dbootimg/dbootimg}
DTBTOOL=`which dtbtool`
DTBTOOL=${DTBTOOL:-${DT_ROOT}/tools/dtbtool/dtbtool}

${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -m `dirname $0`/overlays/db410c-fastrpc.dtbo | ${DBOOTIMG} ${BOOTIMG} -u dtb

if [ "$?" -ne 0 ]; then
	echo "Failed to update DTB"
	exit 1
fi

echo "ov5645 enabled, please reboot"
sync
