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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

#include "luks2_internal.h"

// debug only for devel purposes
#include <math.h>
#include <sys/time.h>

void LUKS2_reenc_context_destroy(struct luks2_reenc_context *rh)
{
	if (!rh)
		return;

	free(rh->buffer);
	rh->buffer = NULL;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM &&
	    rh->rp.p.csum.ch) {
		crypt_hash_destroy(rh->rp.p.csum.ch);
		rh->rp.p.csum.ch = NULL;
	}

	json_object_put(rh->jobj_segs_pre);
	rh->jobj_segs_pre = NULL;
	json_object_put(rh->jobj_segs_after);
	rh->jobj_segs_after = NULL;
	json_object_put(rh->jobj_segment_old);
	rh->jobj_segment_old = NULL;
	json_object_put(rh->jobj_segment_new);
	rh->jobj_segment_new = NULL;
}

static int _load_segments_crashed(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh)
{
	int r;
	uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;

	if (!rh)
		return -EINVAL;

	rh->jobj_segs_pre = json_object_new_object();
	if (!rh->jobj_segs_pre)
		return -ENOMEM;

	json_object_object_foreach(LUKS2_get_segments_jobj(hdr), key, val) {
		if (LUKS2_segment_ignore(val))
			continue;
		json_object_object_add(rh->jobj_segs_pre, key, json_object_get(val));
	}

	r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset);
	if (r) {
		json_object_put(rh->jobj_segs_pre);
		rh->jobj_segs_pre = NULL;
	}

	return r;
}

static size_t _reenc_alignment(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int ss;
	size_t alignment = device_block_size(crypt_data_device(cd));

	log_dbg("data device sector size: %zu", alignment);

	ss = LUKS2_reencrypt_get_sector_size_old(hdr);
	log_dbg("Old sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = ss;
	ss = LUKS2_reencrypt_get_sector_size_new(hdr);
	log_dbg("New sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = (size_t)ss;

	return alignment;
}

static int _load_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t device_size)
{
	int r;

	log_dbg("Calculating segments.");

	if (device_size < rh->offset) {
		log_err(cd, "Reencryption offset %" PRIu64 " is beyond device size %" PRIu64 ".\n", rh->offset, device_size);
		return -EINVAL;
	}

	if (rh->length > (device_size - rh->offset)) {
		rh->length = device_size - rh->offset;
		log_dbg("Adjusting reenc_length parameter: dev size: %" PRIu64 ", reenc_offset: %" PRIu64
			", reenc_length: %" PRIu64 ".", device_size, rh->offset, rh->length);
	}

	r = LUKS2_reenc_create_segments(cd, hdr, rh, device_size);
	if (r) {
		log_err(cd, "Failed to create reencryption segments.\n");
		return r;
	}

	return r;
}

/* returns void because it must not fail on valid LUKS2 header */
static void _load_backup_segments(struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-final");

	if (segment >= 0) {
		rh->jobj_segment_new = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_new = LUKS2_digest_by_segment(NULL, hdr, segment);
	} else {
		rh->jobj_segment_new = NULL;
		rh->digest_new = -ENOENT;
	}

	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-previous");
	if (segment >= 0) {
		rh->jobj_segment_old = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_old = LUKS2_digest_by_segment(NULL, hdr, segment);
	} else {
		rh->jobj_segment_old = NULL;
		rh->digest_old = -ENOENT;
	}
}

/* this code expects valid LUKS2 header */
static int _reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size)
{
	const char *mode, *hash;
	int r;
	uint64_t dummy;

	if (!rh)
		return -EINVAL;

	log_dbg("Loading reencrypt context from LUKS2 header.");

	rh->reenc_keyslot = LUKS2_find_keyslot(cd, hdr, "reencrypt");
	if (rh->reenc_keyslot < 0)
		return -EINVAL;

	if (!strcmp(LUKS2_reencrypt_mode(hdr), "reencrypt"))
		rh->type = REENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "encrypt"))
		rh->type = ENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "decrypt"))
		rh->type = DECRYPT;
	else
		return -ENOTSUP;

	rh->alignment = _reenc_alignment(cd, hdr);

	mode = LUKS2_reencrypt_protection_type(hdr);

	if (!strcmp(mode, "shift")) {
		log_dbg("Initializaing reencryption context with data_shift protection.");
		rh->rp.type = REENC_PROTECTION_DATASHIFT;
		rh->data_shift = LUKS2_reencrypt_data_shift(hdr);
	} else if (!strcmp(mode, "journal")) {
		log_dbg("Initializaing reencryption context with journal protection.");
		rh->rp.type = REENC_PROTECTION_JOURNAL;
	} else if (!strcmp(mode, "checksum")) {
		log_dbg("Initializaing reencryption context with checksum protection.");
		rh->rp.type = REENC_PROTECTION_CHECKSUM;
		hash = LUKS2_reencrypt_protection_hash(hdr);

		r = snprintf(rh->rp.p.csum.hash,
			sizeof(rh->rp.p.csum.hash), "%s", hash);
		if (r < 0 || (size_t)r >= sizeof(rh->rp.p.csum.hash)) {
			log_dbg("Invalid hash parameter");
			return -EINVAL;
		}
		r = crypt_hash_size(hash);
		if (r < 1) {
			log_dbg("Invalid hash size");
			return -EINVAL;
		}
		rh->rp.p.csum.hash_size = r;
		if (crypt_hash_init(&rh->rp.p.csum.ch, hash)) {
			log_dbg("Failed to init hash %s", hash);
			return -EINVAL;
		}

		/*
		 * override previously calculated alignemnt. we have to use what
		 * we protected the hotzone with
		 */
		rh->alignment = LUKS2_reencrypt_protection_sector_size(hdr);
		if (!rh->alignment) {
			log_dbg("Failed to get protection sector_size.");
			return -EINVAL;
		}

		if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &dummy, &rh->buffer_len) < 0)
			return -EINVAL;

		rh->buffer = aligned_malloc((void **)&rh->buffer, rh->buffer_len,
				device_alignment(crypt_metadata_device(cd)));
		if (!rh->buffer)
			return -ENOMEM;
		memset(rh->buffer, 0, rh->buffer_len);
	} else if (!strcmp(mode, "noop")) {
		log_dbg("Initializaing reencryption context with noop protection.");
		rh->rp.type = REENC_PROTECTION_NOOP;
		rh->rp.p.noop.hz_size = LUKS2_DEFAULT_REENCRYPTION_LENGTH;
	} else
		return -EINVAL;

	rh->length = LUKS2_get_reencrypt_length(hdr, rh);
	if (LUKS2_get_reencrypt_offset(hdr, rh->type, device_size, rh->length, &rh->offset)) {
		log_err(cd, "Failed to get reencryption offset.");
		return -EINVAL;
	}
	rh->offset <<= SECTOR_SHIFT;

	_load_backup_segments(hdr, rh);

	log_dbg("reencrypt-previous digest id: %d", rh->digest_old);
	log_dbg("reencrypt-previous segment: %s", rh->jobj_segment_old ? json_object_to_json_string_ext(rh->jobj_segment_old, JSON_C_TO_STRING_PRETTY) : "<missing>");
	log_dbg("reencrypt-final digest id: %d", rh->digest_new);
	log_dbg("reencrypt-final segment: %s", rh->jobj_segment_new ? json_object_to_json_string_ext(rh->jobj_segment_new, JSON_C_TO_STRING_PRETTY) : "<missing>");

	log_dbg("reencrypt length: %" PRIu64, rh->length);
	log_dbg("reencrypt offset: %" PRIu64, rh->offset);
	log_dbg("reencrypt shift: %" PRIi64, rh->data_shift);
	log_dbg("reencrypt alignemnt: %zu", rh->alignment);

	return rh->length < 512 ? -EINVAL : 0;
}

int LUKS2_reenc_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh)
{
	int r = _reenc_load(cd, hdr, rh, 0);
	return r ?: _load_segments_crashed(cd, hdr, rh);
}

int LUKS2_reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size)
{
	int r = _reenc_load(cd, hdr, rh, device_size);
	return r ?: _load_segments(cd, hdr, rh, device_size);
}

int LUKS2_reenc_recover(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	struct volume_key *vks[4])
{
	const struct volume_key *vk_old, *vk_new;
	size_t count, s;
	ssize_t read;
	json_object *jobj;
	unsigned protection;
	uint64_t area_offset, area_length, area_length_read, crash_iv_offset,
		 data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	int r, new_sector_size, old_sector_size, rseg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre), fd = -1;
	char *checksum_tmp = NULL, *data_buffer = NULL;
	struct crypt_storage_wrapper *cw1 = NULL, *cw2 = NULL;

	protection = rh->rp.type;

	if (rseg < 0)
		return -EINVAL;

	vk_new = crypt_volume_key_by_digest(vks, rh->digest_new);
	if (!vk_new && rh->type != DECRYPT)
		return-EINVAL;
	vk_old = crypt_volume_key_by_digest(vks, rh->digest_old);
	if (!vk_old && rh->type != ENCRYPT)
		return-EINVAL;
	old_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_old(hdr));
	new_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_new(hdr));
	crash_iv_offset = json_segment_get_iv_offset(json_segments_get_segment(rh->jobj_segs_pre, rseg));

	log_dbg("crash_offset: %" PRIu64 ", crash_length: %" PRIu64 ",  crash_iv_offset: %" PRIu64, data_offset + rh->offset, rh->length, crash_iv_offset);

	r = crypt_storage_wrapper_init(cd, &cw2, crypt_data_device(cd),
			data_offset + rh->offset, crash_iv_offset, new_sector_size,
			LUKS2_reencrypt_segment_cipher_new(hdr), vk_new, 0);
	if (r) {
		log_err(cd, "Failed to initialize new key storage wrapper.\n");
		return r;
	}

	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &area_offset, &area_length)) {
		r = -EINVAL;
		goto out;
	}

	data_buffer = aligned_malloc((void **)&data_buffer,
			rh->length, device_alignment(crypt_data_device(cd)));
	if (!data_buffer) {
		r = -ENOMEM;
		goto out;
	}

	switch (protection) {
	case  REENC_PROTECTION_CHECKSUM:
		log_dbg("Checksums based recovery.");

		r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
				data_offset + rh->offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, "Failed to initialize old segment storage wrapper.\n");
			goto out;
		}

		count = rh->length / rh->alignment;
		area_length_read = count * rh->rp.p.csum.hash_size;
		if (area_length_read > area_length) {
			log_dbg("Internal error in calculated area_length.");
			r = -EINVAL;
			goto out;
		}

		checksum_tmp = malloc(rh->rp.p.csum.hash_size);
		if (!checksum_tmp) {
			r = -ENOMEM;
			goto out;
		}

		/* TODO: lock for read */
		fd = device_open(crypt_metadata_device(cd), O_RDONLY);
		if (fd < 0) {
			log_err(cd, "Failed to open mdata device.\n");
			goto out;
		}

		/* read old data checksums */
		read = read_lseek_blockwise(fd, device_block_size(crypt_metadata_device(cd)),
					device_alignment(crypt_metadata_device(cd)), rh->buffer, area_length_read, area_offset);
		close(fd);
		if (read < 0 || (size_t)read != area_length_read) {
			log_err(cd, "Failed to read checksums.\n");
			r = -EINVAL;
		}

		read = crypt_storage_wrapper_read(cw2, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_err(cd, "Failed to read hotzone area.\n");
			r = -EINVAL;
			goto out;
		}

		for (s = 0; s < count; s++) {
			if (crypt_hash_write(rh->rp.p.csum.ch, data_buffer + (s * rh->alignment), rh->alignment)) {
				log_err(cd, "Failed to write hash.\n");
				r = EINVAL;
				goto out;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, checksum_tmp, rh->rp.p.csum.hash_size)) {
				log_err(cd, "Failed to finalize hash.\n");
				r = EINVAL;
				goto out;
			}
			if (!memcmp(checksum_tmp, rh->buffer + (s * rh->rp.p.csum.hash_size), rh->rp.p.csum.hash_size)) {
				log_dbg("Sector %zu (size %zu, offset %zu) needs recovery", s, rh->alignment, s * rh->alignment);
				if (crypt_storage_wrapper_decrypt(cw1, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment)) {
					log_err(cd, "Failed to decrypt sector %zu.\n", s);
					r = -EINVAL;
					goto out;
				}
				if (rh->alignment != crypt_storage_wrapper_encrypt_write(cw2, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment)) {
					log_err(cd, "Failed to recover sector %zu.\n", s);
					r = -EINVAL;
					goto out;
				}
			}
		}

		r = 0;
		break;
	case  REENC_PROTECTION_JOURNAL:
		log_dbg("Journal based recovery.");

		/* FIXME: validation candidate */
		if (rh->length > area_length) {
			r = -EINVAL;
			log_err(cd, "Invalid protection parameters (internal error).\n");
			goto out;
		}

		/* TODO locking */
		r = crypt_storage_wrapper_init(cd, &cw1, crypt_metadata_device(cd),
				area_offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, "Failed to initialize old key storage wrapper.\n");
			goto out;
		}
		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg("Failed to read journaled data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}
		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg("recovery write failed.");
			r = -EINVAL;
			goto out;
		}

		r = 0;
		break;
	case  REENC_PROTECTION_DATASHIFT:
		log_dbg("Data shift based recovery.");

		jobj = json_segments_get_segment(rh->jobj_segs_pre, 1);
		/* FIXME: what if reencrypt segment is also the last one */
		/* and this seems too complex */
		/* note, this works for encryption only and following wrapper is alway (noop/cipher_null) */
		if (rseg == 0) {
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					json_segment_get_offset(jobj, 0) + json_segment_get_size(jobj, 0), 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		} else
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					data_offset + rh->offset - rh->length, 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		if (r) {
			log_err(cd, "Failed to initialize old key storage wrapper.\n");
			goto out;
		}

		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg("Failed to read data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}

		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg("recovery write failed.");
			r = -EINVAL;
			goto out;
		}
		r = 0;
		break;
	default:
		r = -EINVAL;
	}
out:
	free(data_buffer);
	free(checksum_tmp);
	crypt_storage_wrapper_destroy(cw1);
	crypt_storage_wrapper_destroy(cw2);

	return r;
}

static int _add_backup_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		unsigned final)
{
	int digest, s = LUKS2_segment_first_unused_id(hdr);
	json_object *jobj;

	if (s < 0)
		return s;

	digest = final ? rh->digest_new : rh->digest_old;
	jobj = final ? rh->jobj_segment_new : rh->jobj_segment_old;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(jobj))) {
		json_object_put(jobj);
		return -EINVAL;
	}

	return LUKS2_digest_segment_assign(cd, hdr, s, digest, 1, 0);
}

static int _assign_segments_simple(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	unsigned pre,
	unsigned commit)
{
	int r, sg;

	if (pre && json_segments_count(rh->jobj_segs_pre) > 0) {
		log_dbg("Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (!pre && json_segments_count(rh->jobj_segs_after) > 0) {
		log_dbg("Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	}

	if (r) {
		log_err(cd, "Failed to assign new enc segments.");
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, rh->type == ENCRYPT);
	if (r) {
		log_dbg("Failed to assign reencryption final backup segment.");
		return r;
	}

	for (sg = 0; sg < LUKS2_segments_count(hdr); sg++) {
		if (LUKS2_segment_is_type(hdr, sg, "crypt") &&
		    LUKS2_digest_segment_assign(cd, hdr, sg, rh->type == ENCRYPT ? rh->digest_new : rh->digest_old, 1, 0)) {
			log_err(cd, "Failed to assign digest %u to segment %u.", rh->digest_new, sg);
			return -EINVAL;
		}
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

/* FIXME: this is stupid. Rewrite */
static int reenc_assign_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, unsigned pre, unsigned commit)
{
	int r, rseg, scount;

	/* FIXME: validate in reencrypt context load */
	if (rh->digest_new < 0 && rh->type != DECRYPT)
		return -EINVAL;

	if (LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0))
		return -EINVAL;

	if (rh->type == ENCRYPT || rh->type == DECRYPT)
		return _assign_segments_simple(cd, hdr, rh, pre, commit);

	if (pre && rh->jobj_segs_pre) {
		log_dbg("Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (rh->jobj_segs_after) {
		log_dbg("Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	}

	scount = LUKS2_segments_count(hdr);

	/* segment in reencryption has to hold reference on both digests */
	rseg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
	if (rseg < 0 && pre)
		return -EINVAL;

	if (rseg >= 0) {
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_new, 1, 0);
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_old, 1, 0);
	}

	if (pre) {
		if (rseg > 0)
			LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > rseg + 1)
			LUKS2_digest_segment_assign(cd, hdr, rseg + 1, rh->digest_old, 1, 0);
	} else {
		LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > 1)
			LUKS2_digest_segment_assign(cd, hdr, 1, rh->digest_old, 1, 0);
	}

	if (r) {
		log_err(cd, "Failed to set segments.\n");
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_err(cd, "Failed to assign reencrypt previous backup segment.");
		return r;
	}
	r = _add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_err(cd, "Failed to assign reencrypt final backup segment.");
		return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_reenc_update_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	return reenc_assign_segments(cd, hdr, rh, 0, 1);
}

/* FIXME: seems to be temporary and for encryption initialization only */
static int _encrypt_set_segments(struct crypt_device *cd, struct luks2_hdr *hdr, int64_t data_shift)
{
	int r;
	uint64_t first_segment_offset, dev_size, first_segment_length,
		 second_segment_offset, second_segment_length,
		 data_offset = LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
	json_object *jobj_segment_first = NULL, *jobj_segment_second = NULL, *jobj_segments;

	if ((r = device_size(crypt_data_device(cd), &dev_size))) {
		log_err(cd, "Failed to read device_size.\n");
		return r;
	}

	if (dev_size < (data_shift < 0 ? -data_shift : data_shift))
		return -EINVAL;

	if (data_shift) {
		/* future data_device layout: [future LUKS2 header][second data segment][empty space][first data segment] */
		first_segment_offset = dev_size - data_offset;
		first_segment_length = data_offset;
		second_segment_offset = data_offset;
		second_segment_length = dev_size - 2 * data_offset + (data_shift < 0 ? data_shift : -data_shift);
	} else {
		/* future data_device layout with deatached header: [first data segment] */
		first_segment_offset = 0;
		first_segment_length = 0; /* dynamic */
	}

	jobj_segments = json_object_new_object();
	if (!jobj_segments)
		return -ENOMEM;

	r = -EINVAL;
	if (data_shift) {
		jobj_segment_first =  LUKS2_segment_create_linear(first_segment_offset, &first_segment_length, 0);
		jobj_segment_second = LUKS2_segment_create_linear(second_segment_offset, &second_segment_length, 0);
		if (!jobj_segment_second) {
			log_err(cd, "Failed generate 2nd segment.");
			goto err;
		}
	} else
		jobj_segment_first =  LUKS2_segment_create_linear(first_segment_offset, first_segment_length ? &first_segment_length : NULL, 0);

	if (!jobj_segment_first) {
		log_err(cd, "Failed generate 1st segment.");
		goto err;
	}

	json_object_object_add(jobj_segments, "0", jobj_segment_first);
	if (jobj_segment_second)
		json_object_object_add(jobj_segments, "1", jobj_segment_second);

	LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0);

	r = LUKS2_segments_set(cd, hdr, jobj_segments, 1);
err:
	return r;
}

static int reenc_setup_segments(struct crypt_device *cd,
				struct luks2_hdr *hdr,
				struct device *hz_device,
				struct volume_key *vks[4],
				struct dm_target *result,
				uint64_t size)
{
	unsigned reenc_seg;
	struct volume_key *vk;
	uint64_t segment_size, segment_offset, segment_start = 0;
	int s, r, count = LUKS2_segments_count(hdr);
	json_object *jobj, *jobj_segments = LUKS2_get_segments_jobj(hdr);

	for (s = 0; s < count; s++) {
		jobj = json_segments_get_segment(jobj_segments, s);
		if (!jobj) {
			log_dbg("Internal error. Segment %d is null.", s);
			r = -EINVAL;
			goto out;
		}

		reenc_seg = (s == json_segments_segment_in_reencrypt(jobj_segments));

		segment_offset = json_segment_get_offset(jobj, 1);
		segment_size = json_segment_get_size(jobj, 1);
		/* 'dynamic' length allowed in last segment only */
		/* TODO: remove (s == count - 1). this should be caught by validation */
		if (!segment_size && (s == count - 1))
			segment_size = (size >> SECTOR_SHIFT) - segment_start;
		if (!segment_size) {
			log_dbg("Internal error. Wrong segment size %d", s);
			r = -EINVAL;
			goto out;
		}

		if (!strcmp(json_segment_type(jobj), "crypt")) {
			vk = crypt_volume_key_by_digest(vks, reenc_seg ? LUKS2_reencrypt_digest_new(hdr) : LUKS2_digest_by_segment(cd, hdr, s));
			if (!vk) {
				log_err(cd, "Missing key for dm-crypt segment %d", s);
				r = -EINVAL;
				goto out;
			}

			if (reenc_seg)
				segment_offset -= crypt_get_data_offset(cd);

			r = dm_crypt_target_set(result+ s, segment_start, segment_size,
						reenc_seg ? hz_device : crypt_data_device(cd),
						vk,
						json_segment_get_cipher(jobj),
						json_segment_get_iv_offset(jobj),
						segment_offset,
						"none",
						0,
						json_segment_get_sector_size(jobj));
			if (r) {
				log_err(cd, _("Failed to set dm-crypt segment.\n"));
				goto out;
			}
		} else if (!strcmp(json_segment_type(jobj), "linear")) {
			r = dm_linear_target_set(result + s, segment_start, segment_size, reenc_seg ? hz_device : crypt_data_device(cd), segment_offset);
			if (r) {
				log_err(cd, _("Failed to set dm-linear segment.\n"));
				goto out;
			}
		} else {
			r = -EINVAL;
			goto out;
		}

		segment_start += segment_size;
	}

	return count;
out:
	return r;
}

/* GLOBAL FIXME: audit function names and parameters names */

/* FIXME:
 * 	1) audit log routines
 * 	2) can't we derive hotzone device name from crypt context? (unlocked name, device uuid, etc?)
 */
int reenc_load_overlay_device(struct crypt_device *cd, struct luks2_hdr *hdr,
	const char *overlay, const char *hotzone, struct volume_key *vks[4], uint64_t size)
{
	char hz_path[PATH_MAX];
	int r;

	struct device *hz_dev = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = CRYPT_ACTIVATE_KEYRING_KEY,
	};

	log_dbg("Loading new table for overlay device %s.", overlay);

	r = snprintf(hz_path, PATH_MAX, "%s/%s", dm_get_dir(), hotzone);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(&hz_dev, hz_path);
	if (r) {
		log_err(cd, "Failed to alocate device %s.\n", hz_path);
		goto out;
	}

	r = reenc_setup_segments(cd, hdr, hz_dev, vks, dmd.segment, size);
	if (r < 0) {
		log_err(cd, "Failed to create dm segments.\n");
		goto out;
	}
	dmd.segment_count = r;

	r = dm_reload_device(cd, overlay, CRYPT_PLAIN, &dmd);
	if (!r) {
		log_dbg("Current %s device has following table in inactive slot:", overlay);
		dm_debug_table(&dmd);
	}

	/* what else on error here ? */
out:
	dm_targets_free(&dmd);
	device_free(hz_dev);

	return r;
}

/* FIXME:
 *	remove completely. the device should be read from header directly
 *
 * 	1) audit log functions
 * 	2) check flags
 */
int reenc_replace_device(struct crypt_device *cd, const char *target, const char *source, uint32_t flags)
{
	int r, exists = 1;
	uint64_t size = 0;
	struct crypt_dm_active_device dmd_source = {};
	struct crypt_dm_active_device dmd_target = {};
	uint32_t dmflags = DM_SUSPEND_SKIP_LOCKFS;

	log_dbg("Replacing table in device %s with table from device %s.", target, source);

	/* check only whether target device exists */
	r = dm_query_device(cd, target, 0, &dmd_target);
	if (r < 0) {
		if (r == -ENODEV)
			exists = 0;
		else
			return r;
	}

	r = dm_query_device(cd, source, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
			    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY, &dmd_source);

	if (r < 0)
		goto err;

	/* what!? */
	dmd_source.flags |= (flags & CRYPT_ACTIVATE_PRIVATE);
	dmd_source.flags |= (flags & CRYPT_ACTIVATE_SHARED);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &size, &dmd_source.flags);

	if (r)
		goto err;

	if (exists && size != dmd_source.size) {
		log_err(cd, "Source and target device sizes don't match. Source %" PRIu64 ", target: %" PRIu64 ".\n",
			dmd_source.size, size);
		r = -EINVAL;
		goto err;
	}

	if (exists) {
		r = dm_reload_device(cd, target, CRYPT_LUKS2, &dmd_source);
		if (!r) {
			log_dbg("Current %s device has following table in inactive slot:", target);
			dm_debug_table(&dmd_source);
		}
		if (!r) {
			log_dbg("Resuming device %s", target);
			if (dmd_source.flags & CRYPT_ACTIVATE_PRIVATE)
				dmflags |= DM_ACTIVATE_PRIVATE;
			r = dm_resume_device(cd, target, dmflags);
		}
	} else {
		r = dm_create_device(cd, target, CRYPT_LUKS2, &dmd_source);
		if (!r) {
			log_dbg("Crreated %s device with following table:", target);
			dm_debug_table(&dmd_source);
		}
	}
err:
	dm_targets_free(&dmd_source);
	dm_targets_free(&dmd_target);

	return r;
}

int reenc_swap_backing_device(struct crypt_device *cd, const char *name,
			      const char *new_backend_name, uint32_t flags)
{
	enum devcheck device_check;
	int r;

	struct device *overlay_dev = NULL;
	char overlay_path[PATH_MAX] = { 0 };

	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.segment_count = 1
	};

	log_dbg("Redirecting %s mapping to new backing device: %s.", name, new_backend_name);

	/* TODO: perhaps get hotzone device and overlay devices in crypt_device handle */
	r = snprintf(overlay_path, PATH_MAX, "%s/%s", dm_get_dir(), new_backend_name);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	//r = device_alloc_internal(&overlay_dev, overlay_path, 0);
	r = device_alloc(&overlay_dev, overlay_path);
	if (r) {
		log_err(cd, "Failed to allocate device for new backing device.\n");
		goto out;
	}

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_block_adjust(cd, overlay_dev, device_check,
				0, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	r = dm_linear_target_set(dmd.segment, 0, dmd.size, overlay_dev, 0);
	if (r)
		goto out;

	r = dm_reload_device(cd, name, CRYPT_PLAIN, &dmd);
	if (!r) {
		log_dbg("Current %s device has following table in inactive slot:", name);
		dm_debug_table(&dmd);
	}
	if (!r) {
		log_dbg("Resuming device %s", name);
		r = dm_resume_device(cd, name, dmd.flags);
	}

out:
	dm_targets_free(&dmd);
	device_free(overlay_dev);

	return r;
}

int reenc_activate_hotzone_device(struct crypt_device *cd, const char *name, uint32_t flags)
{
	enum devcheck device_check;
	int r;

	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.segment_count = 1
	};

	log_dbg("Activating hotzone device %s.", name);

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_block_adjust(cd, crypt_data_device(cd), device_check,
				crypt_get_data_offset(cd), &dmd.size, &dmd.flags);
	if (r)
		goto err;

	r = dm_linear_target_set(dmd.segment, 0, dmd.size, crypt_data_device(cd), crypt_get_data_offset(cd));
	if (r)
		goto err;

	r = dm_create_device(cd, name, "HOTZONE", &dmd);

	if (!r) {
		log_dbg("Created following %s device:", name);
		dm_debug_table(&dmd);
	}
err:
	dm_targets_free(&dmd);

	return r;
}

static int reenc_init_helper_devices(struct crypt_device *cd,
				     const char *name,
				     const char *hotzone,
				     const char *overlay,
				     uint64_t *device_size)
{
	int r;

	/* Activate hotzone device 1:1 linear mapping to data_device */
	r = reenc_activate_hotzone_device(cd, hotzone, CRYPT_ACTIVATE_SHARED | CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, "Failed to activate hotzone device %s.\n", hotzone);
		return r;
	}

	/*
	 * Activate overlay device with exactly same table as original 'name' mapping.
	 * Note that within this step the 'name' device may already include a table
	 * constructed from more than single dm-crypt segment. Therefore transfer
	 * mapping as is.
	 *
	 * If we're about to resume reencryption orig mapping has to be already validated for
	 * abrupt shutdown and rchunk_offset has to point on next chunk to reencrypt!
	 *
	 * TODO: in crypt_activate_by*
	 */
	r = reenc_replace_device(cd, overlay, name, CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_SHARED);
	if (r) {
		log_err(cd, "Failed to activate overlay device %s with actual origin table.\n", overlay);
		goto err;
	}

	/* swap origin mapping to overlay device */
	r = reenc_swap_backing_device(cd, name, overlay, CRYPT_ACTIVATE_KEYRING_KEY);
	if (r) {
		log_err(cd, "Failed to load new maping for device %s.\n", name);
		goto err;
	}

	/*
	 * Now the 'name' (unlocked luks) device is mapped via dm-linear to an overlay dev.
	 * The overlay device has a original live table of 'name' device in-before the swap.
	 */

	return 0;
err:
	/* TODO: force error helper devices on error path */
	dm_remove_device(cd, overlay, 0);
	dm_remove_device(cd, hotzone, 0);

	return r;
}

/* TODO:
 * 	1) audit error path. any error in this routine is fatal and should be unlikely.
 * 	   usualy it would hint some collision with another userspace process touching
 * 	   dm devices directly.
 */
static int reenc_refresh_helper_devices(struct crypt_device *cd, const char *overlay, const char *hotzone)
{
	int r;

	/*
	 * we have to explicitely suspend the overlay device before suspending
	 * the hotzone one. Resuming overlay device (aka switching tables) only
	 * after suspending the hotzone may lead to deadlock.
	 *
	 * In other words: always suspend the stack from top to bottom!
	 */
	r = dm_suspend_device(cd, overlay, DM_SUSPEND_SKIP_LOCKFS);
	if (r) {
		log_err(cd, "Failed to suspend %s.\n", overlay);
		return r;
	}

	log_dbg("Suspended device %s",  overlay);

	/* suspend HZ device */
	r = dm_suspend_device(cd, hotzone, DM_SUSPEND_SKIP_LOCKFS);
	if (r) {
		log_err(cd, "Failed to suspend %s.\n", hotzone);
		return r;
	}

	log_dbg("Suspended device %s",  hotzone);

	/* resume overlay device: inactive table (with hotozne) -> live */
	r = dm_resume_device(cd, overlay, DM_ACTIVATE_PRIVATE);
	if (r)
		log_err(cd, "Failed to resume device %s.\n", overlay);
	else
		log_dbg("Resume device %s.", overlay);

	return r;
}

static int move_data(struct crypt_device *cd, int devfd, int64_t data_shift)
{
	void *buffer;
	int r;
	ssize_t ret;
	uint64_t buffer_len, offset;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	log_dbg("Going to move data from head of data device.");

	buffer_len = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	if (!buffer_len)
		return -EINVAL;

	offset = json_segment_get_offset(LUKS2_get_segment_jobj(hdr, 0), 0);

	/* this is nonsense anyway */
	if (buffer_len != json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0)) {
		log_dbg("buffer_len %zu, segment size %zu", buffer_len, json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0));
		return -EINVAL;
	}

	buffer = aligned_malloc((void **)&buffer, buffer_len, device_alignment(crypt_data_device(cd)));
	if (!buffer)
		return -ENOMEM;

	ret = read_lseek_blockwise(devfd,
			device_block_size(crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, 0);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	log_dbg("Going to write %" PRIu64 " bytes at offset %" PRIu64, buffer_len, offset);
	ret = write_lseek_blockwise(devfd,
			device_block_size(crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, offset);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	r = 0;
err:
	memset(buffer, 0, buffer_len);
	free(buffer);
	return r;
}

int update_reencryption_flag(struct crypt_device *cd, int enable)
{
	uint32_t reqs;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (LUKS2_config_get_requirements(cd, hdr, &reqs))
		return -EINVAL;

	/* nothing to do */
	if (enable && (reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return 0;

	/* nothing to do */
	if (!enable && !(reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return 0;

	if (enable)
		reqs |= CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
	else
		reqs &= ~CRYPT_REQUIREMENT_ONLINE_REENCRYPT;

	log_dbg("Going to %s reencryption requirement flag.", enable ? "store" : "wipe");

	return LUKS2_config_set_requirements(cd, hdr, reqs);
}

static int _create_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int keyslot_new,
		const char *reenc_mode,
		const char *cipher,
		const struct crypt_params_luks2 *params)
{
	int r, segment, digest_old = -1, digest_new = -1;
	json_object *jobj_segment_new = NULL, *jobj_segment_old = NULL;
	uint32_t sector_size = params ? params->sector_size : SECTOR_SIZE;

	if (strcmp(reenc_mode, "decrypt")) {
		digest_new = LUKS2_digest_by_keyslot(cd, hdr, keyslot_new);
		if (digest_new < 0)
			return -EINVAL;
	}

	if (strcmp(reenc_mode, "encrypt")) {
		digest_old = LUKS2_digest_by_segment(cd, hdr, CRYPT_DEFAULT_SEGMENT);
		if (digest_old < 0)
			return -EINVAL;
	}

	segment = LUKS2_segment_first_unused_id(hdr);
	if (segment < 0)
		return -EINVAL;

	/* FIXME: Add detection for case (digest old == digest new && old segment == new segment) */
	if (digest_old >= 0) {
		json_object_copy(LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT), &jobj_segment_old);
		r = LUKS2_segment_set_flag(jobj_segment_old, "reencrypt-previous");
		if (r)
			goto err;
		json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_old);
		LUKS2_digest_segment_assign(cd, hdr, segment++, digest_old, 1, 0);
	}

	if (digest_new >= 0) {
		jobj_segment_new = LUKS2_segment_create_crypt(
							crypt_get_data_offset(cd) * SECTOR_SIZE,
							crypt_get_iv_offset(cd),
							NULL, cipher, sector_size, 0);
		r = LUKS2_segment_set_flag(jobj_segment_new, "reencrypt-final");
		if (r)
			goto err;
		json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_new);
		LUKS2_digest_segment_assign(cd, hdr, segment, digest_new, 1, 0);
	}

	return LUKS2_hdr_write(cd, hdr);
err:
	json_object_put(jobj_segment_new);
	json_object_put(jobj_segment_old);
	return r;
}

/* only for reencryption or encryption initialization. Create reencrypt keyslot describing the operation */
/* it's basically special type of crypt_format */
int crypt_reencrypt_init(struct crypt_device *cd,
	int new_keyslot, /* to lookup digests only (since it's not covered by API atm) */
	const char *reencrypt_mode, /* "encrypt" or "reencrypt" */
	const char *cipher,
	const char *cipher_mode,
	int64_t data_shift,
	struct crypt_params_luks2 *params) /* NULL if not changed */
{
	char _cipher[128];
	int devfd, r, reencrypt_keyslot;
	luks2_reencrypt_info ri;
	struct luks2_hdr *hdr;

	if (onlyLUKS2(cd) || !reencrypt_mode)
		return -EINVAL;

	if (!strcmp(reencrypt_mode, "reencrypt") && ((!cipher && cipher_mode) || new_keyslot < 0))
		return -EINVAL;

	if (!strcmp(reencrypt_mode, "encrypt")) {
		cipher = crypt_get_cipher(cd);
		cipher_mode = crypt_get_cipher_mode(cd);
	}

	if (!strcmp(reencrypt_mode, "decrypt") && (cipher || cipher_mode || data_shift))
		return -EINVAL;

	if (!cipher && !cipher_mode) {
		cipher = crypt_get_cipher(cd);
		cipher_mode = crypt_get_cipher_mode(cd);
	}

	if (!cipher_mode || *cipher_mode == '\0')
		snprintf(_cipher, sizeof(_cipher), "%s", cipher);
	else
		snprintf(_cipher, sizeof(_cipher), "%s-%s", cipher, cipher_mode);

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	reencrypt_keyslot = LUKS2_keyslot_find_empty(hdr, NULL);
	if (reencrypt_keyslot < 0) {
		log_err(cd, "No room for another keyslot.");
		return -EINVAL;
	}

	/*
	 * We must perform data move with exclusive open data device
	 * to exclude another cryptsetup process to colide with
	 * encryption initialization.
	 */
	if (data_shift) {
		if ((uint64_t)-data_shift != LUKS2_get_data_offset(hdr)) {
			log_err(cd, "Illegal data shift value %" PRIi64, data_shift);
			return -EINVAL;
		}
		devfd = device_open_excl(crypt_data_device(cd), O_RDWR);
		if (devfd < 0) {
			r = -EINVAL;
			log_err(cd, "Failed to open %s in exclusive mode (perhaps already mapped or mounted).",
				device_path(crypt_data_device(cd)));
			goto err;
		}
	}

	data_shift <<= SECTOR_SHIFT;

	/* FIXME: <atomic_operation> */
	ri = LUKS2_reenc_status(hdr);
	if (ri > REENCRYPT_NONE) {
		log_err(cd, _("Reencryption operation already in-progress or device is restricted by requirements."));
		r = -EINVAL;
		goto err;
	}

	r = update_reencryption_flag(cd, 1);
	if (r) {
		log_err(cd, "Failed to set online-reencryption requirement.");
		r = -EINVAL;
		goto err;
	}
	/* </atomic_operation> */

	r = LUKS2_keyslot_reencrypt_create(cd, hdr, reencrypt_keyslot,
					   reencrypt_mode, data_shift);
	if (r < 0)
		goto err;
	reencrypt_keyslot = r;

	if (!strcmp(reencrypt_mode, "encrypt")) {
		r = _encrypt_set_segments(cd, hdr, data_shift);
		if (r)
			goto err;
	}

	r = _create_backup_segments(cd, hdr, new_keyslot, reencrypt_mode, _cipher, params);
	if (r) {
		log_err(cd, _("Failed to create reencrypt backup segments."));
		goto err;
	}

	if (data_shift && move_data(cd, devfd, data_shift)) {
		r = -EIO;
		goto err;
	}

	r = reencrypt_keyslot;
err:
	if (r < 0) {
		crypt_keyslot_destroy(cd, reencrypt_keyslot);
		update_reencryption_flag(cd, 0);
		/* TODO: remove backup segments */
	}
	if (devfd >= 0)
		close(devfd);
	return r;
}

static struct volume_key *crypt_alloc_volume_key_from_keyring(const char *key_description)
{
	char *buf;
	size_t buf_len;
	struct volume_key *vk;
	int r;

	r = keyring_get_key(key_description, &buf, &buf_len);
	if (r) {
		log_dbg("Failed to get key %s (user type, error %d)", key_description, r);
		return NULL;
	}

	vk = crypt_alloc_volume_key(buf_len, buf);
	crypt_memzero(buf, buf_len);
	free(buf);
	return vk;
}

static int reencrypt_hotzone_protect(struct crypt_device *cd,
	struct luks2_hdr *hdr, struct luks2_reenc_context *rh,
	const void *buffer, size_t buffer_len)
{
	const void *pbuffer;
	size_t data_offset, chks_offset, len;
	int r;

	if (rh->rp.type == REENC_PROTECTION_NOOP) {
		log_dbg("Noop hotzone protection.");
		return 0;
	}

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		log_dbg("Checksums hotzone protection.");

		for (data_offset = 0, chks_offset = 0; data_offset < buffer_len; data_offset += rh->alignment) {
			if (crypt_hash_write(rh->rp.p.csum.ch, buffer + data_offset, rh->alignment)) {
				log_err(cd, "Failed to hash sector at offset %zu.\n", data_offset);
				return -EINVAL;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, rh->buffer + chks_offset, rh->rp.p.csum.hash_size)) {
				log_err(cd, "Failed to read sector hash.\n");
				return -EINVAL;
			}
			chks_offset += rh->rp.p.csum.hash_size;
		}
		len = chks_offset;
		pbuffer = rh->buffer;
	} else if (rh->rp.type == REENC_PROTECTION_JOURNAL) {
		log_dbg("Journal hotzone protection.");
		len = buffer_len;
		pbuffer = buffer;
	} else if (rh->rp.type == REENC_PROTECTION_DATASHIFT) {
		log_dbg("Data shift hotzone protection.");
		return LUKS2_hdr_write(cd, hdr);
	} else
		return -EINVAL;

	log_dbg("Going to store %zu bytes in reencrypt keyslot.", len);

	r = LUKS2_keyslot_reencrypt_store(cd, hdr, rh->reenc_keyslot, pbuffer, len);

	return r > 0 ? 0 : r;
}

static double time_diff(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec)
		+ (end->tv_usec - start->tv_usec) / 1E6;
}

static struct timeval start_time;

static void time_start(void)
{
	gettimeofday(&start_time, NULL);
}

static void time_end(struct crypt_device *cd, const char *routine)
{
	double tdiff;
	struct timeval end_time;

	gettimeofday(&end_time, NULL);
	tdiff = time_diff(&start_time, &end_time);
	start_time = end_time;

	log_std(cd, "%s: time %02llu:%02llu.%03llu\n",
		routine,
		(unsigned long long)tdiff / 60,
		(unsigned long long)tdiff % 60,
		(unsigned long long)((tdiff - floor(tdiff)) * 1000.0));
}

static int continue_reencryption(struct luks2_reenc_context *rh, uint64_t device_size)
{
	if (rh->type == DECRYPT || (rh->type == ENCRYPT && rh->data_shift))
		return !rh->encrypt_done;
	else
		return (device_size > rh->offset);
}

static int _load_and_verify_key(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct volume_key **vk,
		const char *key_description,
		int digest)
{
	int r = -EINVAL;
	struct volume_key *_vk = crypt_alloc_volume_key_from_keyring(key_description);

	(void) keyring_revoke_and_unlink_key_type("user", key_description);

	if (!_vk)
		return -EINVAL;

	if (LUKS2_digest_verify_by_digest(cd, hdr, digest, _vk) != digest) {
		log_dbg("Volume key doesn't match digest %d.", digest);
		goto err;
	}

	r = crypt_volume_key_set_description(_vk, key_description);
	if (r)
		goto err;

	crypt_volume_key_set_digest(_vk, digest);

	r = crypt_volume_key_load_logon_in_keyring(cd, _vk);
	if (r)
		goto err;

	*vk = _vk;
	return 0;
err:
	crypt_free_volume_key(_vk);

	return r;
}

static int _load_keys_from_keyring(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct volume_key *vks[4])
{
	int new, old, r = 0, i = 0;
	char *key_description_new = NULL, *key_description_old = NULL;
	struct volume_key *vk_old = NULL, *vk_new = NULL;

	old = LUKS2_reencrypt_digest_old(hdr);
	new = LUKS2_reencrypt_digest_new(hdr);

	if (old < 0 && old != -ENOENT)
		return -EINVAL;
	if (new < 0 && new != -ENOENT)
		return -EINVAL;

	if (new >= 0 && !(key_description_new = LUKS2_key_description_by_digest(cd, new)))
		r = -EINVAL;
	if (old >= 0 && !(key_description_old = LUKS2_key_description_by_digest(cd, old)))
		r = -EINVAL;
	if (r)
		goto err;

	if (old >= 0)
		r = _load_and_verify_key(cd, hdr, &vk_old, key_description_old, old);
	if (r)
		goto err;

	if (old >= 0 && new == old)
		vk_new = vk_old;
	else if (new >= 0)
		r = _load_and_verify_key(cd, hdr, &vk_new, key_description_new, new);
	if (r)
		goto err;

	if (vk_new)
		vks[i++] = vk_new;
	if (vk_old && (vk_new != vk_old))
		vks[i] = vk_old;

	r = 0;
err:
	free(key_description_old);
	free(key_description_new);
	if (r) {
		crypt_free_volume_key(vk_new);
		crypt_free_volume_key(vk_old);
	}
	return r;
}

static int LUKS2_reenc_update_context(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		const struct crypt_params_reencrypt *params)
{
	int r;
	uint64_t dummy;

	if (!rh || !params)
		return -EINVAL;

	/* nothing to do or fail because we can't switch off data shift protection */
	if (rh->rp.type == REENC_PROTECTION_DATASHIFT)
		return !strcmp(params->protection, "data_shift") ? 0 : -ENOTSUP;

	LUKS2_reenc_context_destroy(rh);

	rh->alignment = _reenc_alignment(cd, hdr);

	if (!strcmp(params->protection, "noop")) {
		log_dbg("Switching protection to noop.");
		rh->rp.type = REENC_PROTECTION_NOOP;
		rh->rp.p.noop.hz_size = params->hotzone_size;
	} else if (!strcmp(params->protection, "journal")) {
		log_dbg("Switching protection to journal.");
		rh->rp.type = REENC_PROTECTION_JOURNAL;
	} else if (!strcmp(params->protection, "checksum")) {
		log_dbg("Switching protection to checksums.");
		rh->rp.type = REENC_PROTECTION_CHECKSUM;

		r = snprintf(rh->rp.p.csum.hash,
			sizeof(rh->rp.p.csum.hash), "%s", params->hash);
		if (r < 0 || (size_t)r >= sizeof(rh->rp.p.csum.hash)) {
			log_dbg("Invalid hash parameter");
			return -EINVAL;
		}
		r = crypt_hash_size(params->hash);
		if (r < 1) {
			log_dbg("Invalid hash size");
			return -EINVAL;
		}
		rh->rp.p.csum.hash_size = r;
		if (crypt_hash_init(&rh->rp.p.csum.ch, params->hash)) {
			log_dbg("Failed to init hash %s", params->hash);
			return -EINVAL;
		}

		if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &dummy, &rh->buffer_len) < 0)
			return -EINVAL;

		rh->buffer = aligned_malloc((void **)&rh->buffer, rh->buffer_len,
				device_alignment(crypt_metadata_device(cd)));
		if (!rh->buffer)
			return -ENOMEM;
		memset(rh->buffer, 0, rh->buffer_len);
	}  else
		return -EINVAL;
	rh->length = LUKS2_get_reencrypt_length(hdr, rh);
	if (LUKS2_get_reencrypt_offset(hdr, rh->type, device_size, rh->length, &rh->offset)) {
		log_err(cd, "Failed to get reencryption offset.");
		return -EINVAL;
	}
	rh->offset <<= SECTOR_SHIFT;

	_load_backup_segments(hdr, rh);

	log_dbg("reencrypt-previous digest id: %d", rh->digest_old);
	log_dbg("reencrypt-previous segment: %s", rh->jobj_segment_old ? json_object_to_json_string_ext(rh->jobj_segment_old, JSON_C_TO_STRING_PRETTY) : "<missing>");
	log_dbg("reencrypt-final digest id: %d", rh->digest_new);
	log_dbg("reencrypt-final segment: %s", rh->jobj_segment_new ? json_object_to_json_string_ext(rh->jobj_segment_new, JSON_C_TO_STRING_PRETTY) : "<missing>");

	log_dbg("reencrypt length: %" PRIu64, rh->length);
	log_dbg("reencrypt offset: %" PRIu64, rh->offset);
	log_dbg("reencrypt shift: %" PRIi64, rh->data_shift);
	log_dbg("reencrypt alignemnt: %zu", rh->alignment);

	return rh->length < 512 ? -EINVAL : _load_segments(cd, hdr, rh, device_size);
}

/* FIXME:
 * 	1) audit whether helper devices (hotzone and overlay) can't be derived from crypt context.
 * 	2) checksums handling
 *	3) proper error path
 *	4) anotate fatal errors and non-fatal errors properly
 */
int crypt_reencrypt(struct crypt_device *cd,
		    const char *name,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
		    struct crypt_params_reencrypt *params)
{
	const struct volume_key *vk;
	char hotzone[128], overlay[128];
	char *reenc_buffer;
	ssize_t read;
	int i, r;
	luks2_reencrypt_info ri;
	struct luks2_hdr *hdr;
	struct volume_key *vks[4] = {};
	struct luks2_reenc_context rh = {};
	unsigned online = (name != NULL), quit = 0;
	uint64_t read_offset, device_size = 0;
#ifdef DEBUG_DMTABLES
	char cmd[1024];
	unsigned step = 0;
#endif
// #define DEBUG 1
#ifdef DEBUG
	char backup_name[128];
	unsigned bcp=0;
#endif

#define DEBUG_ZERO 1
#ifdef DEBUG_ZERO
	char *zero_buffer;
#endif
	struct crypt_storage_wrapper *cw1 = NULL, *cw2 = NULL;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	ri = LUKS2_reenc_status(hdr);
	if (ri > REENCRYPT_CLEAN) {
		log_err(cd, "Can't resume reencryption. Unexpected reencryption status.");
		return -EINVAL;
	}

	/* TODO: reencrypt and encrypt w/ data_shift == 0 can start w/ NONE state */
	/* TODO: encryption w/ data-shift must be in CLEAN state */

	/* TODO requirements */

	snprintf(hotzone, sizeof(hotzone), "%s-hotzone", name);
	snprintf(overlay, sizeof(overlay), "%s-overlay", name);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &device_size, NULL);
	if (r)
		return r;

	device_size <<= SECTOR_SHIFT;

	r = LUKS2_reenc_load(cd, hdr, &rh, device_size);
	if (r) {
		log_err(cd, "Failed to load reenc context.");
		return -EINVAL;
	}

	/* Update protection params if requested */
	if (params && (r = LUKS2_reenc_update_context(cd, hdr, &rh, device_size, params)) && r != -ENOTSUP) {
		log_err(cd, "Failed to update reenc context.");
		return -EINVAL;
	}

	r = _load_keys_from_keyring(cd, hdr, vks);
	if (r) {
		log_err(cd, "Failed to load keys from kernel keyring.");
		goto err;
	}

	/* initialise device masquarade if online */
	if (online) {
		r = reenc_init_helper_devices(cd, name, hotzone, overlay, &device_size);
		if (r)
			return r;
	}

	vk = crypt_volume_key_by_digest(vks, rh.digest_old);
	r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
			(crypt_get_data_offset(cd) << SECTOR_SHIFT),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_old(hdr),
			LUKS2_reencrypt_segment_cipher_old(hdr),
			vk, DISABLE_KCAPI);
	if (r) {
		log_dbg("Failed to initialize storage wrapper for old cipher.");
		goto err;
	}

	vk = crypt_volume_key_by_digest(vks, rh.digest_new);
	r = crypt_storage_wrapper_init(cd, &cw2, crypt_data_device(cd),
			(crypt_get_data_offset(cd) << SECTOR_SHIFT),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_new(hdr),
			LUKS2_reencrypt_segment_cipher_new(hdr),
			vk, DISABLE_KCAPI);
	if (r) {
		log_dbg("Failed to initialize storage wrapper for new cipher.");
		goto err;
	}

#ifdef DEBUG_ZERO
	zero_buffer = malloc(rh.length);
	if (!zero_buffer)
		return -ENOMEM;
	memset(zero_buffer, 0, rh.length);
#endif
	reenc_buffer = aligned_malloc((void **)&reenc_buffer, rh.length, device_alignment(crypt_data_device(cd)));
	if (!reenc_buffer)
		return -ENOMEM;

	/*
	 * FIXME: lazy allocation and Linux memory overcommitment stil may lead
	 * to page fault in critical section if following line get optimized out
	 */
	memset(reenc_buffer, 42, rh.length);

	log_dbg("Reencryption device size: %" PRIu64, device_size);

	/* update reencrypt keyslot protection parameters in memory only */
	r = reenc_keyslot_update(cd, &rh);
	if (r < 0) {
		log_dbg("Keyslot update failed.");
		return r;
	}

#ifdef DEBUG
		if (LUKS2_hdr_write(cd, hdr)) {
			log_err(cd, "Failed to store luks2 hdr");
			return -EINVAL;
		}
		snprintf(backup_name, sizeof(backup_name), "clear-debug-luks2-backup-uuid-%s", crypt_get_uuid(cd));
		crypt_header_backup(cd, CRYPT_LUKS2, backup_name);
#endif

	/* FIXME: the finish-or-not decisision must be more transparent */
	rh.encrypt_done = json_segments_count(rh.jobj_segs_after) == 1;

	while (continue_reencryption(&rh, device_size)) {

		rh.encrypt_done = json_segments_count(rh.jobj_segs_after) == 1;
		log_dbg("Encryption done = %d", rh.encrypt_done);

		log_dbg("Actual luks2 header segments:\n%s", LUKS2_debug_dump_segments(hdr));

		if (quit) {
			log_dbg("Reencryption interrupted.");
			break;
		}

		time_start();
		r = reenc_assign_segments(cd, hdr, &rh, 1, 0);
		if (r) {
			log_err(cd, "Failed to assign pre reenc segments.\n");
			goto err;
		}
		time_end(cd, "reenc_assign (pre)");

		log_dbg("Actual header segments post pre assign:\n%s", LUKS2_debug_dump_segments(hdr));

		if (online) {
			/* TODO: fold in single routine */
			r = reenc_load_overlay_device(cd, hdr, overlay, hotzone, vks, device_size);
			if (r) {
				log_err(cd, "Failed to reload overlay device %s.\n", overlay);
				goto err;
			}
			time_end(cd, "overlay device load");

			r = reenc_refresh_helper_devices(cd, overlay, hotzone);
			if (r) {
				log_err(cd, "Failed to refresh helper devices.\n");
				goto err;
			}
			time_end(cd, "overlay device refresh");
		}

#ifdef DEBUG_DMTABLES
		snprintf(cmd, 1024, "dmsetup info > /tmp/log-step%d", step);
		system(cmd);
		snprintf(cmd, 1024, "dmsetup table >> /tmp/log-step%d", step++);
		system(cmd);
#endif

		log_dbg("Reencrypting chunk starting at offset: %zu, size :%zu.", rh.offset, rh.length);
		log_dbg("data_offset: %zu", crypt_get_data_offset(cd) << SECTOR_SHIFT);

		if (!rh.offset && rh.type == ENCRYPT && rh.data_shift) {
			read_offset = LUKS2_segment_offset(hdr, 1, 0) + LUKS2_segment_size(hdr, 1, 0) - (LUKS2_get_data_offset(hdr) << SECTOR_SHIFT);
			log_dbg("This is encryption last step. Changing read_offset to %" PRIu64, read_offset);
		} else
			read_offset = rh.offset + rh.data_shift;

		read = crypt_storage_wrapper_read(cw1, read_offset, reenc_buffer, rh.length);
		if (read < 0) {
			log_err(cd, "Failed to read chunk starting at %zu.\n", read_offset);
			break;
		}
		time_end(cd, "device read");

		/* TODO: can we decrypt buffer in async mode? */

		/* Currently it's a commit point in LUKS2 header */
		r = reencrypt_hotzone_protect(cd, hdr, &rh, reenc_buffer, read);
		if (r < 0) {
			log_err(cd, "Failed to protect reencryption hotzone, retval = %d", r);
			return -EINVAL;
		}
		time_end(cd, "hotzone protect");
#ifdef DEBUG
		snprintf(backup_name, sizeof(backup_name), "%u-dirty-debug-luks2-backup-uuid-%s", bcp, crypt_get_uuid(cd));
		crypt_header_backup(cd, CRYPT_LUKS2, backup_name);
#endif

		r = crypt_storage_wrapper_decrypt(cw1, read_offset, reenc_buffer, read);
		if (r) {
			log_err(cd, "Decryption failed.\n");
			break;
		}
		time_end(cd, "decryption");

#ifdef DEBUG_ZERO
		if (memcmp(zero_buffer, reenc_buffer, read)) {
			log_err(cd, "reencryption is fishy.");
			return -EINVAL;
		}
#endif

		if (read != crypt_storage_wrapper_encrypt_write(cw2, rh.offset, reenc_buffer, read)) {
			log_err(cd, "Failed to write chunk starting at sector %zu.\n", rh.offset);
			break;
		}
		time_end(cd, "device write");
		crypt_storage_wrapper_datasync(cw2);
		time_end(cd, "datasync");

		/* metadata commit safe point */
		r = reenc_assign_segments(cd, hdr, &rh, 0, 1);
		if (r) {
			log_err(cd, "Failed to assign reenc segments.\n");
			goto err;
		}
		time_end(cd, "reenc_assign (post)");
#ifdef DEBUG
		snprintf(backup_name, sizeof(backup_name), "%u-clear-debug-luks2-backup-uuid-%s", bcp++, crypt_get_uuid(cd));
		crypt_header_backup(cd, CRYPT_LUKS2, backup_name);
#endif

		if (online) {
			log_dbg("Resuming device %s", hotzone);
			r = dm_resume_device(cd, hotzone, DM_ACTIVATE_PRIVATE);
			if (r) {
				log_err(cd, "Failed to resume device %s.\n", hotzone);
				goto err;
			}
			time_end(cd, "hotzone device resume");
		}

		/* TODO: for future i/o throttling. This is the spot */

		if (rh.type == ENCRYPT && rh.rp.type == REENC_PROTECTION_DATASHIFT) {
			if (rh.offset)
				rh.offset += rh.data_shift;
		} else if (rh.type == DECRYPT) {
			if (rh.offset < rh.length)
				rh.length = rh.offset;
			rh.offset -= rh.length;
		} else
			rh.offset += read;

		if (progress && progress(device_size, rh.offset, NULL))
			quit = 1;

		r = _load_segments(cd, hdr, &rh, device_size);
		if (r) {
			log_err(cd, "Failed to calculate new segments.\n");
			goto err;
		}
		time_end(cd, "_load_segments (post resume)");

		log_dbg("Next reencryption offset will be %" PRIu64 " sectors.", rh.offset);
		log_dbg("Next reencryption chunk size will be %" PRIu64 " sectors).", rh.length);
	}

	r = 0;
err:
	crypt_storage_wrapper_destroy(cw1);
	crypt_storage_wrapper_destroy(cw2);

	/* use directly 'after' segments */
	if (online && !r) {
		if (reenc_assign_segments(cd, hdr, &rh, 0, 1))
			log_err(cd, "Failed to assign reenc segments.\n");

		if (reenc_load_overlay_device(cd, hdr, overlay, hotzone, vks, device_size))
			log_err(cd, "Failed to load overlay device.\n");
	}

	if (!r) {
		if (rh.digest_old >= 0)
			for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
				if (LUKS2_digest_by_keyslot(NULL, hdr, i) == rh.digest_old)
					crypt_keyslot_destroy(cd, i);
		crypt_keyslot_destroy(cd, rh.reenc_keyslot);
		if (reenc_erase_backup_segments(cd, hdr))
			log_err(cd, "Failed to erase backup segments");
		if (update_reencryption_flag(cd, 0))
			log_err(cd, "Failed to disable reencryption requirement flag.");
	}

	if (online) {
		if (!r) {
			if (dm_resume_device(cd, overlay, DM_ACTIVATE_PRIVATE))
				log_err(cd, "Failed to resume %s device.\n", overlay);
			if (reenc_replace_device(cd, name, overlay, 0))
				log_err(cd, "Failed to replace %s device.\n", name);
		}
		else {/* en error path we need to reinstate origin mapping with one or more keys without hotzone device */ }
		dm_remove_device(cd, overlay, 0);
		dm_remove_device(cd, hotzone, 0);
	}

	LUKS2_reenc_context_destroy(&rh);
	free(reenc_buffer);

	return r;
}

int reenc_erase_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-previous");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}
	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-final");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}

	return 0;
}
