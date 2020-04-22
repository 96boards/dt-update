/*
 * Copyright (C) 2018 Linaro Limited
 * Copyright (C) 2018 Loic Poulain <loic.poulain@linaro.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* TODO: save mem + fix multiple missing pointer releases */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <limits.h>

#include "puff.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define le64_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)
#define cpu_to_le64(val) (val)
#define be16_to_cpu(val) bswap_16(val)
#define be32_to_cpu(val) bswap_32(val)
#define be64_to_cpu(val) bswap_64(val)
#define cpu_to_be16(val) bswap_16(val)
#define cpu_to_be32(val) bswap_32(val)
#define cpu_to_be64(val) bswap_64(val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#define le64_to_cpu(val) bswap_64(val)
#define cpu_to_le16(val) bswap_16(val)
#define cpu_to_le32(val) bswap_32(val)
#define cpu_to_le64(val) bswap_64(val)
#define be16_to_cpu(val) (val)
#define be32_to_cpu(val) (val)
#define be64_to_cpu(val) (val)
#define cpu_to_be16(val) (val)
#define cpu_to_be32(val) (val)
#define cpu_to_be64(val) (val)
#else
#error "Unknown byte order"
#endif

struct gzip_hdr {
	uint16_t	magic;	/* 0x8b1f */
	uint8_t		method;
	uint8_t		flags;
	uint32_t	time;
	uint8_t		extra_flags;
	uint8_t		os;
	uint8_t		extra[0];
} __attribute__((packed)); /* little endian */
static const char magic_gzip[2] = { 0x1f, 0x8b };
#define METHOD_DEFLATE	0x08
#define FTEXT		0x01
#define FHCRC		0x02
#define FEXTRA		0x04
#define FNAME		0x08
#define FCOMMENT	0x10

struct aboot_hdr {
	uint64_t	magic; /* ANDROID! */
	uint32_t	kernel_size;
	uint32_t	kernel_addr;
	uint32_t	ramdisk_size;
	uint32_t	ramdisk_addr;
	uint32_t	second_size;
	uint32_t	second_addr;
	uint32_t	kernel_tags_addr;
	uint32_t	page_size;
	uint64_t	unused;
	uint8_t		name[16];
	uint8_t		cmdline[512];
	uint64_t	id;
	uint8_t		extra_cmdline[1024];
} __attribute__((packed)); /* little endian */
static const char magic_aboot[8] = { 'A', 'N', 'D', 'R', 'O', 'I', 'D', '!' };

struct dtb_hdr {
	uint32_t magic; /* 0xd00dfeed */
	uint32_t totalsize;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t off_mem_rsvmap;
	uint32_t version;
	uint32_t last_comp_version;
	uint32_t boot_cpuid_phys;
	uint32_t size_dt_strings;
	uint32_t size_dt_struct;
} __attribute__((packed)); /* Big endian */
uint32_t magic_dtb = 0xd00dfeed;

static int read2(int fd, void *buf, size_t blen)
{
	int ret, size = 0;

	do {
		ret = read(fd, buf + size, blen - size);
		if (ret <= 0)
			break;

		size += ret;
	} while (size < blen);

	return size;
}

static ssize_t gzip_size(struct gzip_hdr *gzip, size_t gzip_len)
{
	unsigned long max_ulong = -1;
	size_t extra_sz = 0;
	int err;
	void *ptr;

	/* RFC 1952 */

	if (memcmp(&gzip->magic, magic_gzip, sizeof(magic_gzip))) {
		fprintf(stderr, "error: No gzipped kernel found\n");
		return -EINVAL;
	}

	if (gzip->method != METHOD_DEFLATE) {
		fprintf(stderr, "error: Unsupported gzip compression method\n");
		return -EINVAL;
	}

	if (gzip->flags & FEXTRA) {
		uint16_t xlen = le16_to_cpu(*((uint16_t *)&gzip->extra[0]));
		extra_sz = sizeof(xlen) + xlen;
	}

	if (gzip->flags & FNAME)
		while(gzip->extra[extra_sz++]); /* NULL terminated name */

	if (gzip->flags & FCOMMENT)
		while(gzip->extra[extra_sz++]); /* NULL terminated name */

	if (gzip->flags & FHCRC)
		extra_sz += 2; /* crc16*/

	/* compressed block start here */
	ptr = (void *)gzip + sizeof(*gzip) + extra_sz;

	/* don't really want to inflate, just walk the file to get its size */
	err = puff(NULL, &max_ulong, ptr, &gzip_len);
	if (err) {
		fprintf(stderr, "error inflating kernel (%d)\n", err);
		return -EINVAL;
	}

	ptr += gzip_len;

	/* gzip footer */
	ptr += 4; /* crc32 */
	ptr += 4; /* uncompressed data size */

	return (ptr - (void *)gzip);
}

static bool kernel_is_gzip(void *kernel)
{
	struct gzip_hdr *gzip = kernel;

	if (memcmp(&gzip->magic, magic_gzip, sizeof(magic_gzip))) {
		return false;
	}

	return true;
}

static ssize_t kernelgz_size(void *kernel)
{
	if (kernel_is_gzip(kernel))
		return gzip_size(kernel, UINT_MAX);
	else
		return 0;
}

static bool kernel_has_appended_dtb(void *kernel)
{
	struct dtb_hdr *dtb;

	if (!kernel_is_gzip(kernel))
		return false;

	dtb = kernel + kernelgz_size(kernel);

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb)
		return false;

	return true;
}


static ssize_t dtb_size(void *dtb)
{
	return be32_to_cpu(((struct dtb_hdr *)dtb)->totalsize);
}

static ssize_t aboot_size(const struct aboot_hdr *aboot)
{
	int page_size, n, m, o;

	page_size = le32_to_cpu(aboot->page_size);
	n = (le32_to_cpu(aboot->kernel_size) + page_size - 1) / page_size;
	m = (le32_to_cpu(aboot->ramdisk_size) + page_size - 1) / page_size;
	o = (le32_to_cpu(aboot->second_size) + page_size - 1) / page_size;

 	return (1 + n + m + o) * page_size;
}

static void *aboot_load_fromfd(int fd_aboot)
{
	struct aboot_hdr *aboot;
	int ret, to_read;

	aboot = malloc(sizeof(*aboot));
	if (!aboot)
		return NULL;

	ret = read2(fd_aboot, aboot, sizeof(*aboot));
	if (ret != sizeof(*aboot)) {
		fprintf(stderr, "invalid boot image\n");
		free(aboot);
		return NULL;
	}

	if (memcmp(&aboot->magic, magic_aboot, sizeof(magic_aboot))) {
		fprintf(stderr, "invalid boot image (bad magic)\n");
		free(aboot);
		return NULL;
	}

	aboot = realloc(aboot, aboot_size(aboot));
	if (!aboot)
		return NULL;

	to_read = aboot_size(aboot) - sizeof(struct aboot_hdr);
	ret = read2(fd_aboot, (void *)aboot + sizeof(struct aboot_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid boot image\n");
		free(aboot);
		return NULL;
	}

	return aboot;
}

#define MBYTE 1000000

static void *kernel_load_fromfd(int fd_kernel)
{
	struct gzip_hdr *gzip;
	size_t size = sizeof(*gzip);
	void *kernel;
	int ret, off;

	gzip = malloc(size);
	if (!gzip)
		return NULL;

	ret = read2(fd_kernel, gzip, sizeof(*gzip));
	if (ret != sizeof(*gzip)) {
		fprintf(stderr, "invalid kernel.gz image\n");
		free(gzip);
		return NULL;
	}

	if (!kernel_is_gzip(gzip)) {
		fprintf(stderr, "not a valid kernel gzip image\n");
		free(gzip);
		return NULL;
	}

	kernel = gzip;
	size = sizeof(*gzip);
	off = sizeof(*gzip);

	do {
		size = size + 5 * MBYTE;
		kernel = realloc(kernel, size);
		if (!kernel) {
			fprintf(stderr, "kernel memory alloc error\n");
			free(gzip);
			return NULL;
		}

		ret = read2(fd_kernel, kernel + off, size - off);
		if (ret != (size - off))
			break;
		off += ret;
	} while(1);

	return kernel;
}

static void *aboot_get_dtb(struct aboot_hdr *aboot)
{
	int page_sz, kernel_sz;
	struct dtb_hdr *dtb;
	void *kernel;

	page_sz = le32_to_cpu(aboot->page_size);
	kernel = (void *)aboot + page_sz;

	kernel_sz = kernelgz_size(kernel);
	if (kernel_sz < 0)
		return NULL;

	dtb = kernel + kernel_sz;

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb) {
		fprintf(stderr, "DTB not found in boot image\n");
		return NULL;
	}

	return dtb;
}

static void *aboot_get_kernel(void *aboot)
{
	return aboot + le32_to_cpu(((struct aboot_hdr*)aboot)->page_size);
}

static void *aboot_get_ramdisk(void *boot)
{
	struct aboot_hdr *aboot = boot;
	int page_size, n;

	page_size = le32_to_cpu(aboot->page_size);
	n = (le32_to_cpu(aboot->kernel_size) + page_size - 1) / page_size;

	return (void *)aboot + (1 + n) * page_size;
}

static void *aboot_get_end(void *boot)
{
	return boot + aboot_size(boot);
}

static void *aboot_update_dtb(void *boot, void *dtb, bool force)
{
	struct aboot_hdr *aboot, *old_aboot = boot;
	struct dtb_hdr *old_dtb;
	void *kernel, *ptr;
	ssize_t page_sz, kernel_sz, align_sz;

	page_sz = le32_to_cpu(old_aboot->page_size);

	kernel = aboot_get_kernel(old_aboot);
	if (!kernel)
		return NULL;

	kernel_sz = kernelgz_size(kernel);

	old_dtb = aboot_get_dtb(old_aboot);
	if (!old_dtb)
		return NULL;

	/* Check DTB version */
	if (old_dtb->version != ((struct dtb_hdr *)dtb)->version) {
		fprintf(stderr, "DTB version mismatch, Old=%d New=%d\n",
			be32_to_cpu(old_dtb->version),
			be32_to_cpu(((struct dtb_hdr *)dtb)->version));
		if (force) {
			printf("forcing update\n");
		} else {
			fprintf(stderr, "Use -f option to force update\n");
			return NULL;
		}
	}

	aboot = malloc(aboot_size(old_aboot) + dtb_size(dtb));
	if (!aboot)
		return NULL;

	/* Now we can generate our new abootimg */
	ptr = aboot;

	/* copy first block, aboot hdr + kernel.gz */
	memcpy(ptr, old_aboot, page_sz + kernel_sz);
	ptr += page_sz + kernel_sz;

	/* modify kernel size (kernel.gz + dtb) */
	aboot->kernel_size = cpu_to_le32(kernel_sz + dtb_size(dtb));

	/* copy new DTB */
	memcpy(ptr, dtb, dtb_size(dtb));
	ptr += dtb_size(dtb);

	/* align on page */
	align_sz = page_sz - le32_to_cpu(aboot->kernel_size) % page_sz;
	if (align_sz != page_sz) {
		memset(ptr, 0, align_sz);
		ptr += align_sz;
	}

	/* copy remaining data */
	memcpy(ptr, aboot_get_ramdisk(old_aboot),
	       aboot_get_end(old_aboot) - aboot_get_ramdisk(old_aboot));

	return aboot;
}

static void *aboot_update_kernel(void *boot, void *kernel)
{
	struct aboot_hdr *aboot, *old_aboot = boot;
	ssize_t page_sz, kernel_sz, align_sz, dtb_sz;
	void *old_kernel, *dtb, *ptr;
	int diff;

	page_sz = le32_to_cpu(old_aboot->page_size);
	old_kernel = aboot_get_kernel(old_aboot);
	kernel_sz = kernelgz_size(kernel);
	dtb = aboot_get_dtb(old_aboot);
	dtb_sz = dtb ? dtb_size(dtb) : 0;

	diff = kernel_sz - kernelgz_size(old_kernel);

	aboot = malloc(aboot_size(old_aboot) + diff + page_sz);
	if (!aboot)
		return NULL;

	/* Now we can generate our new abootimg */
	ptr = aboot;

	/* copy first block, aboot hdr */
	memcpy(ptr, old_aboot, page_sz);
	ptr += page_sz;

	/* copy our new kernel */
	memcpy(ptr, kernel, kernel_sz);
	ptr += kernel_sz;

	/* copy appended dtb */
	memcpy(ptr, dtb, dtb_sz);
	ptr += dtb_sz;

	/* modify kernel size (kernel.gz + dtb) */
	aboot->kernel_size = cpu_to_le32(kernel_sz + dtb_sz);

	/* align on page */
	align_sz = page_sz - le32_to_cpu(aboot->kernel_size) % page_sz;
	if (align_sz != page_sz) {
		memset(ptr, 0, align_sz);
		ptr += align_sz;
	}

	/* copy remaining data */
	memcpy(ptr, aboot_get_ramdisk(old_aboot),
	       aboot_get_end(old_aboot) - aboot_get_ramdisk(old_aboot));

	return aboot;
}

static void *dtb_load_fromfd(int fd_dtb)
{
	struct dtb_hdr *dtb;
	int ret, to_read;

	dtb = malloc(sizeof(*dtb));
	if (!dtb)
		return NULL;

	ret = read2(fd_dtb, dtb, sizeof(*dtb));
	if (ret != sizeof(*dtb)) {
		fprintf(stderr, "invalid DTB\n");
		free(dtb);
		return NULL;
	}

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb) {
		fprintf(stderr, "invalid DTB (bad magic)\n");
		free(dtb);
		return NULL;
	}

	dtb = realloc(dtb, dtb_size(dtb));
	if (!dtb)
		return NULL;

	to_read = dtb_size(dtb) - sizeof(struct dtb_hdr);
	ret = read2(fd_dtb, (void *)dtb + sizeof(struct dtb_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid DTB image\n");
		free(dtb);
		return NULL;
	}

	return dtb;
}

static int dbootimg_fdt_extract(int fd_boot, int fd_fdt)
{
	void *aboot, *dtb;
	int ret;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	dtb = aboot_get_dtb(aboot);
	if (!dtb) {
		free(aboot);
		return -EINVAL;
	}

	ret = write(fd_fdt, dtb, dtb_size(dtb));
	ret = (ret == dtb_size(dtb)) ? 0 : -EINVAL;

	free(aboot);

	return ret;
}

static int dbootimg_fdt_update(int fd_boot, int fd_fdt, int fd_dst)
{
	void *aboot, *new_aboot, *dtb;
	int ret = -EINVAL;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	dtb = dtb_load_fromfd(fd_fdt);
	if (!dtb)
		goto error_dtb;

	new_aboot = aboot_update_dtb(aboot, dtb, false);
	if (!new_aboot)
		goto error_update;

	if (fd_boot == fd_dst)
		lseek(fd_dst, 0, 0);

	ret = write(fd_dst, new_aboot, aboot_size(new_aboot));
	ret = (ret == aboot_size(new_aboot)) ? 0 : -EINVAL;

	free(new_aboot);
error_update:
	free(dtb);
error_dtb:
	free(aboot);
	return ret;
}

static int dbootimg_cmdline_extract(int fd_boot, int fd_out)
{
	struct aboot_hdr *aboot;
	int ret;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	ret = write(fd_out, aboot->cmdline, strlen((char *)aboot->cmdline) + 1);
	ret = (ret == strlen((char *)aboot->cmdline) + 1) ? 0 : -EINVAL;

	free(aboot);

	return ret;
}

static int dbootimg_cmdline_update(int fd_boot, char *cmdline, int fd_dst)
{
	struct aboot_hdr *aboot;
	int ret;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	memcpy(aboot->cmdline, cmdline, strlen(cmdline) + 1);

	if (fd_boot == fd_dst)
		lseek(fd_dst, 0, 0);

	ret = write(fd_dst, aboot, aboot_size(aboot));
	ret = (ret == aboot_size(aboot)) ? 0 : -EINVAL;

	free(aboot);

	return ret;
}

static int dbootimg_kernel_extract(int fd_boot, int fd_out)
{
	int kernel_sz, ret;
	struct aboot_hdr *aboot;
	void *kernel;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	kernel = aboot_get_kernel(aboot);
	if (!(kernel_sz = kernelgz_size(kernel))) /* non gz+dtb */
		kernel_sz = le32_to_cpu(aboot->kernel_size);

	ret = write(fd_out, aboot_get_kernel(aboot), kernel_sz);
	ret = (ret == kernel_sz) ? 0 : -EINVAL;

	free(aboot);

	return ret;
}

static int dbootimg_kernel_update(int fd_boot, int fd_kernel, int fd_dst)
{
	struct aboot_hdr *aboot, *new_aboot;
	struct dtb_hdr *dtb;
	void *kernel;
	int ret = -EINVAL;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	kernel = kernel_load_fromfd(fd_kernel);
	if (!kernel)
		goto error_kernel;

	new_aboot = aboot_update_kernel(aboot, kernel);
	if (!aboot)
		goto error_update;

	/* check if new kernel has an appended DTB */
	dtb = kernel + kernelgz_size(kernel);
	if (be32_to_cpu(dtb->magic) == magic_dtb) {
		free(aboot);
		aboot = new_aboot;

		new_aboot = aboot_update_dtb(aboot, dtb, true);
		if (!new_aboot)
			goto error_update;
	}

	if (fd_boot == fd_dst)
		lseek(fd_dst, 0, 0);

	ret = write(fd_dst, new_aboot, aboot_size(new_aboot));
	if (ret != aboot_size(new_aboot)) {
		fprintf(stderr, "error during kernel update\n");
		ret = -EINVAL;
	}

	free(new_aboot);
error_update:
	free(kernel);
error_kernel:
	free(aboot);
	return ret;
}

static int dbootimg_info(int fd_boot)
{
	struct aboot_hdr *aboot;
	void *kernel;

	aboot = aboot_load_fromfd(fd_boot);
	if (!aboot)
		return -EINVAL;

	kernel = aboot_get_kernel(aboot);

	printf("aboot size:    %ld bytes\n", aboot_size(aboot));

	if (kernel_is_gzip(kernel) && kernel_has_appended_dtb(kernel)) {
		printf("kernel.gz+dtb: %d bytes\n",
			le32_to_cpu(aboot->kernel_size));
	} else if (kernel_is_gzip(kernel)) {
		printf("kernel.gz:     %d bytes (no appended DTB)\n",
			le32_to_cpu(aboot->kernel_size));
	} else {
		printf("kernel:        %d bytes (non-gzip, no appended DTB)\n",
			le32_to_cpu(aboot->kernel_size));
	}

	printf("ramdisk:       %d bytes\n", le32_to_cpu(aboot->ramdisk_size));
	printf("second:        %d bytes\n", le32_to_cpu(aboot->second_size));
	printf("page size:     %d bytes\n", le32_to_cpu(aboot->page_size));
	printf("cmdline: %s\n", aboot->cmdline);

	return 0;
}

static void usage(void)
{
	printf("Usage: dbootimg <bootimg> [options]\n" \
	       "options:\n" \
	       "   -x, --extract <arg>\n" \
	       "         Extract blob, valid blob types are:\n" \
	       "                 dtb: device-tree blob\n"  \
	       "                 kernel: kernel.gz blob\n"  \
	       "                 cmdline: command line string\n"  \
	       "   -u, --update <arg> [file|\"cmdline\"]\n" \
	       "         Update blob, valid blob types are:\n" \
	       "                 dtb: device-tree blob\n"  \
	       "                 kernel: kernel.gz blob\n"  \
	       "                 cmdline: command line string\n"  \
	       "   -i, --info\n" \
	       "   -o, --out <arg>\n" \
	       "         Output file\n" \
	       );

}

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "extract", required_argument, NULL, 'x' },
	{ "update", required_argument, NULL, 'u' },
	{ "out", required_argument, NULL, 'o' },
	{ "info", no_argument, NULL, 'i' },
	{ },
};

int main(int argc, char *argv[])
{
	bool extract = false, update = false, info = false;
	int fd_boot = -1, fd_out = -1, ret;
	char *path_boot = NULL, *path_out = NULL;
	char *type = NULL;

	for (;;) {
		int opt = getopt_long(argc, argv, ":x:u:o:hi", main_options,
				      NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'x':
			extract = true;
			type = optarg;
			break;
		case 'u':
			update = true;
			type = optarg;
			break;
		case 'o':
			path_out = optarg;
			break;
		case 'i':
			info = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			break;
		}
	}

	if (!info && !type) {
		fprintf(stderr, "you must specify a blob type\n");
		usage();
		return -EINVAL;
	}

	path_boot = argv[optind++];
	if (!path_boot) {
		fprintf(stderr, "no boot image path specified\n");
		return -EINVAL;
	}

	if (path_out) {
		fd_out = open(path_out, O_WRONLY|O_CREAT, 0644);
		if (fd_out < 0) {
			fprintf(stderr, "unable to out file %s\n", path_out);
			close(fd_boot);
			return -EINVAL;
		}
	}

	if (path_boot) {
		if (update && (fd_out < 0))
			fd_boot = open(path_boot, O_RDWR);
		else
			fd_boot = open(path_boot, O_RDONLY);

		if (fd_boot < 0) {
			fprintf(stderr, "unable to open boot image %s\n",
				path_boot);
			return -EINVAL;
		}
	}

	if (info) {
		dbootimg_info(fd_boot);
	} else if (extract) {
		if (fd_out < 0)
			fd_out = STDOUT_FILENO;

		if (!strcmp("cmdline", type)) {
			ret = dbootimg_cmdline_extract(fd_boot, fd_out);
		} else if (!strcmp("dtb", type)) {
			ret = dbootimg_fdt_extract(fd_boot, fd_out);
		} else if (!strcmp("kernel", type)) {
			ret = dbootimg_kernel_extract(fd_boot, fd_out);
		} else {
			fprintf(stderr, "invalid blob type (%s)\n", type);
			ret = -EINVAL;
		}
	} else if (update) {
		if (fd_out < 0)
			fd_out = fd_boot;

		if (!strcmp("cmdline", type)) {
			char cmdline[512] = {};

			if (optind < argc) /* cmdline string passed as arg */
				strcpy(cmdline, argv[optind++]);
			else /* STDIN ? */
				read2(STDIN_FILENO, cmdline, sizeof(cmdline));

			ret = dbootimg_cmdline_update(fd_boot, cmdline, fd_out);
		} else if (!strcmp("dtb", type)) {
			char *dtb_path = argv[optind++];
			int fd_in = STDIN_FILENO;

			if (dtb_path) {
				fd_in = open(dtb_path, O_RDONLY);
				if (fd_in < 0) {
					fprintf(stderr, "unable to open %s\n",
					        dtb_path);
					close(fd_boot);
					return -EINVAL;
				}
			}

			ret = dbootimg_fdt_update(fd_boot, fd_in, fd_out);

		} else if (!strcmp("kernel", type)){
			char *kernel_path = argv[optind++];
			int fd_in = STDIN_FILENO;

			if (kernel_path) {
				fd_in = open(kernel_path, O_RDONLY);
				if (fd_in < 0) {
					fprintf(stderr, "unable to open %s\n",
					        kernel_path);
					close(fd_boot);
					return -EINVAL;
				}
			}

			ret = dbootimg_kernel_update(fd_boot, fd_in, fd_out);
		} else {
			fprintf(stderr, "invalid blob type (%s)\n", type);
			ret = -EINVAL;
		}
	} else {
		ret = -EINVAL;
		usage();
	}

	return ret;
}
