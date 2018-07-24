#!/bin/bash

# Update kernel with the one available in /boot directory

BOOTIMG=${1:-/dev/disk/by-partlabel/boot}
DT_ROOT=`dirname $0`/../..
DBOOTIMG=`which dbootimg`
DBOOTIMG=${DBOOTIMG:-${DT_ROOT}/tools/dbootimg/dbootimg}
KERNEL=/boot/vmlinuz-$(uname -r)

if [ ! -e ${KERNEL} ]; then
	echo "Kernel ${KERNEL} does not exist"
	exit 1
fi

if [ ! -e ${BOOTIMG} ]; then
	echo "Invalid bootimg: ${BOOTIMG}"
	exit 1
fi

echo "Updating kernel..."
${DBOOTIMG} ${BOOTIMG} -u kernel ${KERNEL}

echo "kernel updated, please reboot"
sync
