#!/bin/bash

BOOTIMG=${1:-/dev/disk/by-partlabel/boot}
DT_ROOT=`dirname $0`/../..
DBOOTIMG=`which dbootimg`
DBOOTIMG=${DBOOTIMG:-${DT_ROOT}/tools/dbootimg/dbootimg}
DTBTOOL=`which dtbtool`
DTBTOOL=${DTBTOOL:-${DT_ROOT}/tools/dtbtool/dtbtool}

# Check DTB already has camera subsystem node present
${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -n camss@1b00000 -p > /dev/null 
if [ "$?" -ne 0 ]; then
	echo "Failed to enable ov5645, no camss node, upgrade your bootimg."
	exit 1
fi

# Check rear camera node is already defined
${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -n camera_rear@3b -p > /dev/null
if [ "$?" -ne 0 ]; then
	echo "Failed to enable ov5645, no rear camera node, upgrade your bootimg."
	return -1
fi

${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -m `dirname $0`/overlays/db410c-ov5645.dtbo | ${DBOOTIMG} ${BOOTIMG} -u dtb

if [ "$?" -ne 0 ]; then
	echo "Failed to update DTB"
	exit 1
fi

echo "ov5645 enabled, please reboot"
sync
