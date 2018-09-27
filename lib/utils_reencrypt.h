/*
 * utils_reencrypt - online reencryption utilities
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Ondrej Kozina
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _UTILS_REENCRYPT_H
#define _UTILS_REENCRYPT_H

#include <unistd.h>

struct crypt_device;
struct luks2_hdr;
struct luks2_reenc_context;

int LUKS2_reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size);

int LUKS2_reenc_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh);

int LUKS2_reenc_update_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh);

int LUKS2_reenc_recover(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	struct volume_key *vks[4]);

void LUKS2_reenc_context_destroy(struct luks2_reenc_context *rh);

int reenc_load_overlay_device(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *overlay,
	const char *hotzone,
	struct volume_key *vks[4],
	uint64_t size);

int reenc_replace_device(struct crypt_device *cd, const char *target, const char *source, uint32_t flags);

int reenc_swap_backing_device(struct crypt_device *cd, const char *name, const char *new_backend_name, uint32_t flags);

int reenc_activate_hotzone_device(struct crypt_device *cd, const char *name, uint32_t flags);

int reenc_erase_backup_segments(struct crypt_device *cd, struct luks2_hdr *hdr);
#endif /* _UTILS_REENCRYPT_H */
