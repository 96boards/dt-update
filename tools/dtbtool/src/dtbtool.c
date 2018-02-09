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
#include <regex.h>

#include "libfdt.h"

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

static ssize_t dtb_size(void *dtb)
{
	return be32_to_cpu(((struct dtb_hdr *)dtb)->totalsize);
}

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

static void *dtb_load_fromfd(int fd_dtb, int reserve)
{
	struct dtb_hdr *dtb;
	int ret, to_read;

	dtb = malloc(sizeof(*dtb));
	if (!dtb)
		return NULL;

	ret = read2(fd_dtb, dtb, sizeof(*dtb));
	if (ret != sizeof(*dtb)) {
		fprintf(stderr, "invalid DTB %d\n", ret);
		free(dtb);
		return NULL;
	}

	/* Check DTB magic */
	if (be32_to_cpu(dtb->magic) != magic_dtb) {
		fprintf(stderr, "invalid DTB (bad magic)\n");
		return NULL;
	}

	dtb = realloc(dtb, dtb_size(dtb) + reserve);
	if (!dtb)
		return NULL;

	to_read = dtb_size(dtb) - sizeof(struct dtb_hdr);
	ret = read2(fd_dtb, (void *)dtb + sizeof(struct dtb_hdr), to_read);
	if (ret != to_read) {
		fprintf(stderr, "invalid DTB image\n");
		free(dtb);
		return NULL;
	}

	/* init and add free space */
	memset((void *)dtb + dtb_size(dtb), 0, reserve);
	dtb->totalsize = cpu_to_be32(dtb_size(dtb) + reserve);

	return dtb;
}

const static char *dtb_node_get_alias(void *dtb, int node)
{
	char path[1024];
	int err, alias, propoff = 0;

	err = fdt_get_path(dtb, node, path, sizeof(path));
	if (err)
		return NULL;

	alias = fdt_path_offset(dtb, "/aliases");
	if (alias < 0)
		return NULL;

	fdt_for_each_property_offset(propoff, dtb, alias) {
		const struct fdt_property *prop;
		int plen;

		prop = fdt_get_property_by_offset(dtb, propoff, &plen);

		if (!strncmp(path, prop->data, plen)) {
			return fdt_string(dtb, fdt32_to_cpu(prop->nameoff));
		}
	}

	return NULL;
}

static int dtb_get_node(void *dtb, const char *node_name)
{
	int node = 0, depth = 0;

	if (fdt_get_alias(dtb, node_name))
		node_name = fdt_get_alias(dtb, node_name);

	while ((node = fdt_next_node(dtb, node, &depth)) >= 0) {
		const struct fdt_property *prop;
		char path[1024];
		const char *name;
		int lenp, ret;

		ret = fdt_get_path(dtb, node, path, sizeof(path));
		if (ret)
			return -EINVAL;

		if (!strcmp(node_name, path))
			return node;

		prop = fdt_get_property(dtb, node, "label", &lenp);
		if (prop && !strcmp(node_name, prop->data))
			return node;

		name = fdt_get_name(dtb, node, &lenp);
		if (!name)
			continue;

		if (!strcmp(node_name, name))
			return node;
	};

	return -1;
}

static bool str_is_bytes(char *str)
{
	const char *bytes = "^\\[(([[:xdigit:]]{2})[[:space:]]?)+\\]$";
	regex_t preg;
	int err;

	err = regcomp(&preg, bytes, REG_EXTENDED);
	if (err)
		return false;


	err = regexec(&preg, str, 0, NULL, 0);
	if (err)
		return false;

	return true;
}

static bool str_is_string(char *str)
{
	if (*str != '[' && *str != '<')
		return true;
	/* TODO: more checks */

	return false;
}

static bool str_is_cell_array(char *str)
{
	const char *cell = "^[<]((([0][xX][[:xdigit:]]{1,8})|([[:digit:]]+))[[:space:]]?)*[>]";
	regex_t preg;
	int err;

	err = regcomp(&preg, cell, REG_EXTENDED);
	if (err)
		return false;

	err = regexec(&preg, str, 0, NULL, 0);
	if (err)
		return false;

	return true;
}

static void str_remove_char(char *str, char c)
{
	int i = 0, j = 0;
	while (str[i++]) {
		while(str[i] == c) {
			j = i;
			while (str[j]) {
				str[j] = str[j + 1];
				j++;
			}
		}
	}
}

static int dtb_convert_value(char *str, struct fdt_property *prop)
{

	/* TODO: fix & clean parsing */
	if (str_is_bytes(str)) { /* byte stream [24 42 5f 6e] */
		str++;
		str_remove_char(str, ' ');
		do {
			int byte;
			char next;

			if (sscanf(str, "%02x%c", &byte, &next) != 2)
				break;
			str += 2;

			prop->data[prop->len++] = byte;
		} while (1);
	} else if (str_is_string(str)) { /* string "value" */
		if (*str == '\"') {
			memcpy(&prop->data[prop->len], str + 1, strlen(str));
			prop->len += strlen(str);
		} else {
			memcpy(&prop->data[prop->len], str, strlen(str) + 1);
			prop->len += strlen(str) + 1;
		}
	} else if (str_is_cell_array(str)) { /* <0x1234 0x648945 12> */
		str++;
		do {
			uint32_t cell;
			char next;
			int ret;

			while (*str == ' ')
				str++;

			if (!strncmp(str, "0x", 2))
				ret = sscanf(str, "%x%c", &cell, &next);
			else
				ret = sscanf(str, "%d%c", &cell, &next);

			if (ret != 2)
				break;

			while ((*str != '>') && (*str != ' '))
				str++;

			cell = cpu_to_be32(cell);
			memcpy(&prop->data[prop->len], &cell, sizeof(cell));
			prop->len += sizeof(cell);
		} while (*str);
	} else {
		return -EINVAL;
	}

	return 0;
}

static int dtb_str2prop(char *str, struct fdt_property *prop)
{
	char *saveptr, *strvalue;

	while ((strvalue = strtok_r(str, ",", &saveptr))) {
		int ret;

		str = NULL;
		ret = dtb_convert_value(strvalue, prop);
		if (ret) {
			fprintf(stderr, "invalid prop value: %s\n", strvalue);
			return -EINVAL;
		}
	}

	return 0;
}

static void dtb_print_prop(const void *prop, int plen, int fd_out)
{
	/* TODO */
	dprintf(fd_out, "[");
	while (plen--) {
		dprintf(fd_out, "%02x", *((uint8_t *)prop++));
	}
	dprintf(fd_out, "]");
}

static int dtbtool_set_prop(void *dtb, char *node_name, char *prop_name,
			    char *value)
{
	char buf[1024] = {}; /* magic */
	struct fdt_property *prop = (void *)&buf;
	int node, ret;

	if (!node_name) {
		fprintf(stderr, "you must specify a node name/path\n");
		return -EINVAL;
	}

	node = dtb_get_node(dtb, node_name);
	if (node < 0) {
		fprintf(stderr, "node '%s' not found in DTB\n", node_name);
		return -EBADR;
	}

	ret = dtb_str2prop(value, prop);
	if (ret)
		return -EINVAL;

	return fdt_setprop(dtb, node, prop_name, prop->data, prop->len);
}

static int dtbtool_get_prop(void *dtb, char *node_name, char *prop_name,
			    int fd_out)
{
	int node, plen;
	const void *prop;

	if (!node_name) {
		fprintf(stderr, "you must specify a node name/path\n");
		return -EINVAL;
	}

	node = dtb_get_node(dtb, node_name);
	if (node < 0) {
		fprintf(stderr, "node '%s' not found in DTB\n", node_name);
		return -EBADR;
	}

	prop = fdt_getprop(dtb, node, prop_name, &plen);
	if (!prop) {
		fprintf(stderr, "'%s' node has no '%s' property\n",
			node_name, prop_name);
		return -EBADR;
	}

	dtb_print_prop(prop, plen, fd_out);
	dprintf(fd_out, "\n");

	return 0;
}

static void dtb_print_node(void *dtb, int node, int fd_out)
{
	const struct fdt_property *prop;
	const char *nname;
	int lenp;

	nname = fdt_get_name(dtb, node, &lenp);
	if (!nname)
		return;

	if (dtb_node_get_alias(dtb, node))
		dprintf(fd_out, "%s: ", dtb_node_get_alias(dtb, node));

	prop = fdt_get_property(dtb, node, "label", &lenp);
	if (prop)
		dprintf(fd_out, "%s: ", prop->data);

	dprintf(fd_out, "%s", nname);

	prop = fdt_get_property(dtb, node, "status", &lenp);
	if (prop && strcmp("ok", prop->data) && strcmp("okay", prop->data))
		dprintf(fd_out, " [disabled]");

	dprintf(fd_out, "\n");
}

static int dtbtool_print(void *dtb, char *node_name, int fd_out)
{
	int node = 0, depth = 0;

	if (node_name) {
		node = dtb_get_node(dtb, node_name);
		if (node < 0) {
			fprintf(stderr, "node '%s' not found in DTB\n",
				node_name);
			return -EINVAL;
		}
		dtb_print_node(dtb, node, fd_out);
		return 0;
	}

	while ((node = fdt_next_node(dtb, node, &depth)) >= 0) {
		int i = depth;
		while (i-- > 0) dprintf(fd_out, "__");
		dtb_print_node(dtb, node, fd_out);
	}

	return 0;
}

static int dtbtool_merge(void *dtb, void *dtbo, int fd_out)
{
	return fdt_overlay_apply(dtb, dtbo);
}

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "enable", no_argument, NULL, 'e' },
	{ "disable", no_argument, NULL, 'd' },
	{ "set-prop", required_argument, NULL, 's' },
	{ "get-prop", required_argument, NULL, 'g' },
	{ "out", required_argument, NULL, 'o' },
	{ "node", required_argument, NULL, 'n' },
	{ "merge", required_argument, NULL, 'm'},
	{ "print", required_argument, NULL, 'p' },
	{ },
};

static void usage(void)
{
	printf("Usage: dtbtool [options]\n" \
	       "options:\n" \
	       "   -m, --merge <dtbo>\n" \
	       "   -n, --node <node>\n" \
	       "   -e, --enable\n" \
	       "         enable node (status=\"ok\")\n" \
	       "   -d, --disable\n" \
	       "         disable node (status=\"disabled\")\n" \
	       "   -g, --get-prop <prop>\n" \
	       "         get node property value\n" \
	       "   -s, --set-prop <prop>[=\"value\"]\n"
	       "         set node property value:\n" \
	       "                 string: prop=\"mystr\"\n" \
	       "                 cell-array: prop=\"<0x03 0x45682233>\"\n" \
	       "                 byte-stream: prop=\"[3f 45 6a]\"\n" \
	       "                 composed: prop=\"mystr,<0x45 0x28>\"\n" \
	       "   -p, --print\n" \
	       "         show dtb (node) information\n" \
	       "   -o, --out <arg>\n" \
	       "         Output file\n" \
	       );

}

int main(int argc, char *argv[])
{
	bool set_prop = false, get_prop = false, print = false;
	char prop_enable[] = "status=okay", prop_disable[] = "status=disabled";
	int ret = -EINVAL, fd_dtb = -1, fd_out = -1, fd_dtbo = -1;
	char *path_dtb = NULL, *path_out = NULL, *path_dtbo = NULL;
	char *prop = NULL, *node = NULL;
	void *dtb, *dtbo = NULL;

	for (;;) {
		int opt = getopt_long(argc, argv, "m:n:x:u:o:s:g:hedp",
				      main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'e':
			set_prop = true;
			prop = prop_enable;
			break;
		case 'd':
			set_prop = true;
			prop = prop_disable;
			break;
		case 'o':
			path_out = optarg;
			break;
		case 'n':
			node = optarg;
			break;
		case 's':
			set_prop = true;
			prop = optarg;
			break;
		case 'g':
			get_prop = true;
			prop = optarg;
			break;
		case 'p':
			print = true;
			break;
		case 'm':
			path_dtbo = optarg;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			break;
		}
	}

	path_dtb = argv[optind++];
	if (path_dtb) {
		fd_dtb = open(path_dtb, O_RDWR);
		if (fd_dtb < 0) {
			fprintf(stderr, "unable to open DTB %s\n",
				path_dtb);
			return -EINVAL;
		}
	} else {
		fd_dtb = STDIN_FILENO;
	}

	if (path_dtbo) {
		fd_dtbo = open(path_dtbo, O_RDWR);
		if (fd_dtbo < 0) {
			perror("unable to open DTB overlay");
			goto error_dtb;
		}

		dtbo = dtb_load_fromfd(fd_dtbo, 0);
	}

	if (!path_out && path_dtb && set_prop)
		path_out = path_dtb;

	if (dtbo)
		dtb = dtb_load_fromfd(fd_dtb, dtb_size(dtbo) * 2);
	else
		dtb = dtb_load_fromfd(fd_dtb, 2048); /* magic ? */
	if (!dtb)
		goto error_dtb;

	if (path_out) {
		fd_out = open(path_out, O_WRONLY|O_CREAT, 0644);
		if (fd_out < 0) {
			fprintf(stderr, "unable to out file %s\n", path_out);
			goto error_out;
		}
	} else {
		fd_out = STDOUT_FILENO;
	}

	if (set_prop) {
		char *key, *value = NULL;

		key = strtok_r(prop, "=", &value);
		if (!key) {
			fprintf(stderr, "invalid prop=value format\n");
			goto out;
		}

		ret = dtbtool_set_prop(dtb, node, key, value);
		if (!ret)
			write(fd_out, dtb, dtb_size(dtb));
	} else if (get_prop) {
		ret = dtbtool_get_prop(dtb, node, prop, fd_out);
	} else if (print) {
		dtbtool_print(dtb, node, fd_out);
	} else if (dtbo) {
		ret = dtbtool_merge(dtb, dtbo, fd_out);
		if (!ret)
			write(fd_out, dtb, dtb_size(dtb));
	} else {
		usage();
	}

out:
	close(fd_out);
error_out:
	free(dtb);
error_dtb:
	if (dtbo)
		free(dtbo);
	if (fd_dtbo > 0)
		close(fd_dtbo);
	close(fd_dtb);

	return ret;
}
