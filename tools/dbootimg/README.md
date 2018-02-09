# dbootimg - manipulate Dragonboard Boot Images.

### Usage

`dbootimg <abootimg> <--extract|--update|--info> <blobtype> [--out outfile]`

dbootimg can work on boot image file or block device.

### Dragonboard boot image format

`+-----------------+`\
`| boot header.....| 1 page`\
`+-----------------+`\
`| kernel.gz + DTB.| n pages`\
`+-----------------+`\
`| ramdisk.........| m pages`\
`+-----------------+`\
`| second stage....| o pages`\
`+-----------------+`

### Examples

- Extract device-tree blob from boot partition (/dev/mmcblkp8)\
`$ dbootimg /dev/mmcblkp8 -x dtb > dtb.img`\
or\
`$ dbootimg /dev/mmcblkp8 -x dtb -o dtb.img`

- Update boot partition with new device-tree blob\
`$ cat dtb.img | dbootimg /dev/mmcblkp8 -u dtb`\
or\
`$ dbootimg /dev/mmcblkp8 -u dtb dtb.img`

- Update command line\
`$ dbootimg /dev/mmcblkp8 -u cmdline "root=/dev/mmcblk0p10 console=ttyMSM0,115200n8"`

- Update kernel (Linux, u-boot...)\
`$ dbootimg /dev/mmcblkp8 -u kernel Image.gz`\
or\
`$ gzip Image -c | dbootimg /dev/mmcblkp8 -u kernel`
