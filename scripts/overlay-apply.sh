#!/bin/bash

OVERLAY=${1}
BOOTIMG=${2:-/dev/disk/by-partlabel/boot}
DT_ROOT=`dirname $0`/../..
DBOOTIMG=`which dbootimg`
DBOOTIMG=${DBOOTIMG:-${DT_ROOT}/tools/dbootimg/dbootimg}
DTBTOOL=`which dtbtool`
DTBTOOL=${DTBTOOL:-${DT_ROOT}/tools/dtbtool/dtbtool}

usage()
{
	echo "usage: ${0} overlay.dtbo [boot-image]"
	echo "boot-image defaults to ${BOOTIMG}"
}

if [ $# -lt 1 ]; then
	usage
	exit 2
fi

if [ ! -e ${OVERLAY} ]; then
	echo "${OVERLAY} doesn't exist."
	exit 3
fi

if [ ! -e ${BOOTIMG} ]; then
	echo "${BOOTIMG} doesn't exist."
	exit 4
fi

${DBOOTIMG} ${BOOTIMG} -x dtb | ${DTBTOOL} -m ${OVERLAY} | ${DBOOTIMG} ${BOOTIMG} -u dtb

if [ "$?" -ne 0 ]; then
	echo "Failed to apply ${OVERLAY} to ${BOOTIMG}"
	exit 1
fi

sync
echo "${OVERLAY} applied to ${BOOTIMG}"
