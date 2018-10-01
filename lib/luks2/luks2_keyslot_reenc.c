/*
 * LUKS - Linux Unified Key Setup v2, reencryption keyslot handler
 *
 * Copyright (C) 2016-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2018, Ondrej Kozina. All rights reserved.
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

#include "luks2_internal.h"

static int reenc_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	char *volume_key,
	size_t volume_key_len)
{
	return -ENOENT; /* TODO: */
}

int reenc_keyslot_alloc(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *reenc_mode, /* reencrypt or encrypt */
	int64_t data_shift)
{
	int r;
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_area;
	uint64_t area_offset, area_length;

	log_dbg("Allocating reencrypt keyslot %d.", keyslot);

	if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX)
		return -ENOMEM;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	/* encryption doesn't require area (we shift data and backup will be available) */
	if (!data_shift) {
		r = LUKS2_find_area_max_gap(cd, hdr, &area_offset, &area_length);
		if (r < 0)
			return r;
	} else { /* we can't have keyslot w/o area...bug? */
		r = LUKS2_find_area_gap(cd, hdr, 1, &area_offset, &area_length);
		if (r < 0)
			return r;
	}

	jobj_keyslot = json_object_new_object();
	if (!jobj_keyslot)
		return -ENOMEM;

	jobj_area = json_object_new_object();

	if (data_shift) {
		json_object_object_add(jobj_area, "type", json_object_new_string("shift"));
		json_object_object_add(jobj_area, "data_shift", json_object_new_int64_ex(data_shift));
	} else
		/* except data shift protection, initial setting is irrelevant. Type can be changed during reencryption */
		json_object_object_add(jobj_area, "type", json_object_new_string("noop"));

	json_object_object_add(jobj_area, "offset", json_object_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_length));

	json_object_object_add(jobj_keyslot, "type", json_object_new_string("reencrypt"));
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(1)); /* useless but mandatory */
	json_object_object_add(jobj_keyslot, "mode", json_object_new_string(reenc_mode));

	json_object_object_add(jobj_keyslot, "area", jobj_area);

	json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot);
	if (LUKS2_check_json_size(hdr)) {
		log_dbg("New keyslot too large to fit in free metadata space.");
		json_object_object_del_by_uint(jobj_keyslots, keyslot);
		return -ENOSPC;
	}

	log_dbg("JSON: %s", json_object_to_json_string_ext(hdr->jobj, JSON_C_TO_STRING_PRETTY));

	return 0;
}

static int reenc_keyslot_store_data(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const void *buffer, size_t buffer_len)
{
	int devfd, r;
	json_object *jobj_area, *jobj_offset, *jobj_length;
	uint64_t area_offset, area_length;
	struct device *device = crypt_metadata_device(cd);

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "offset", &jobj_offset) ||
	    !json_object_object_get_ex(jobj_area, "size", &jobj_length))
		return -EINVAL;

	area_offset = json_object_get_uint64(jobj_offset);
	area_length = json_object_get_uint64(jobj_length);

	if (!area_offset || !area_length || ((uint64_t)buffer_len > area_length))
		return -EINVAL;

	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s.\n"),
			device_path(device));
		return r;
	}

	devfd = device_open_locked(device, O_RDWR);
	if (devfd >= 0) {
		if (write_lseek_blockwise(devfd, device_block_size(device),
					  device_alignment(device), (void *)buffer,
					  buffer_len, area_offset) < 0)
			r = -EIO;
		else
			r = 0;
		close(devfd);
	} else
		r = -EINVAL;

	device_write_unlock(device);

	if (r)
		log_err(cd, _("IO error while encrypting keyslot.\n"));

	return r;
}

static int reenc_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password __attribute__((unused)),
	size_t password_len __attribute__((unused)),
	const char *buffer, /* checksums or old ciphertext backup */
	size_t buffer_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot;
	int r = 0;

	if (!cd || !buffer || !buffer_len)
		return -EINVAL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	log_dbg("Reencrypt keyslot %d store.", keyslot);

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	r = reenc_keyslot_store_data(cd, jobj_keyslot, buffer, buffer_len);
	if (r < 0)
		return r;

	r = LUKS2_hdr_write(cd, hdr);
	if (r < 0)
		return r;

	return keyslot;
}

int reenc_keyslot_update(struct crypt_device *cd,
	const struct luks2_reenc_context *rh)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_area_type;
	struct luks2_hdr *hdr;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, rh->reenc_keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	json_object_object_get_ex(jobj_area, "type", &jobj_area_type);

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		log_dbg("Updating reencrypt keyslot for checksum protection.");
		json_object_object_add(jobj_area, "type", json_object_new_string("checksum"));
		json_object_object_add(jobj_area, "hash", json_object_new_string(rh->rp.p.csum.hash));
		json_object_object_add(jobj_area, "sector_size", json_object_new_int64(rh->alignment));
		//FIXME: add hash size explicitly?
	} else if (rh->rp.type == REENC_PROTECTION_NOOP) {
		log_dbg("Updating reencrypt keyslot for noop protection.");
		json_object_object_add(jobj_area, "type", json_object_new_string("noop"));
		json_object_object_del(jobj_area, "hash");
	} else if (rh->rp.type == REENC_PROTECTION_JOURNAL) {
		log_dbg("Updating reencrypt keyslot for journal protection.");
		json_object_object_add(jobj_area, "type", json_object_new_string("journal"));
		json_object_object_del(jobj_area, "hash");
	} else
		log_dbg("No update of reencrypt keyslot needed.");

	return 0;
}

static int reenc_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
	return 0;
}

static int reenc_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	return 0;
}

static int reenc_keyslot_validate(struct crypt_device *cd, json_object *jobj_keyslot)
{
	return 0;
}

const keyslot_handler reenc_keyslot = {
	.name  = "reencrypt",
	.open  = reenc_keyslot_open,
	.store = reenc_keyslot_store, /* initialization only or also per every chunk write */
	.wipe  = reenc_keyslot_wipe,
	.dump  = reenc_keyslot_dump,
	.validate  = reenc_keyslot_validate
};

static json_object *reencrypt_segment(struct luks2_hdr *hdr, unsigned new)
{
	return LUKS2_get_segment_by_flag(hdr, new ? "reencrypt-final" : "reencrypt-previous");
}

json_object *LUKS2_reencrypt_segment_new(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 1);
}

json_object *LUKS2_reencrypt_segment_old(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 0);
}

const char *LUKS2_reencrypt_segment_cipher_new(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 1));
}

const char *LUKS2_reencrypt_segment_cipher_old(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 0));
}

int LUKS2_reencrypt_get_sector_size_new(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 1));
}

int LUKS2_reencrypt_get_sector_size_old(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 0));
}

static int _reencrypt_digest(struct luks2_hdr *hdr, unsigned new)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, new ? "reencrypt-final" : "reencrypt-previous");

	if (segment < 0)
		return segment;

	return LUKS2_digest_by_segment(NULL, hdr, segment);
}

int LUKS2_reencrypt_digest_new(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 1);
}

int LUKS2_reencrypt_digest_old(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 0);
}

/* noop, checksums, journal or shift */
const char *LUKS2_reencrypt_protection_type(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type;
	int ks = LUKS2_find_keyslot(NULL, hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;

	return json_object_get_string(jobj_type);
}

const char *LUKS2_reencrypt_protection_hash(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash;
	int ks = LUKS2_find_keyslot(NULL, hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return NULL;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return NULL;

	return json_object_get_string(jobj_hash);
}

uint32_t LUKS2_reencrypt_protection_sector_size(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash, *jobj_sector_size;
	int ks = LUKS2_find_keyslot(NULL, hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return 0;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "sector_size", &jobj_sector_size))
		return 0;

	return json_object_get_uint32(jobj_sector_size);
}

static json_object *_enc_create_segments_shift_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg, i = 0;
	json_object *jobj_copy, *jobj_seg_new = NULL, *jobj_segs_after = json_object_new_object();
	uint64_t tmp;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	if (json_segments_count(rh->jobj_segs_pre) == 0)
		return jobj_segs_after;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		goto err;

	while (i < reenc_seg) {
		jobj_copy = json_segments_get_segment(rh->jobj_segs_pre, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_after, i++, json_object_get(jobj_copy));
	}

	if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1), &jobj_seg_new)) {
		if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg), &jobj_seg_new))
			goto err;
		json_segment_remove_flag(jobj_seg_new, "in-reencryption");
		tmp = rh->length;
	} else {
		json_object_object_add(jobj_seg_new, "offset", json_object_new_uint64(rh->offset + data_offset));
		json_object_object_add(jobj_seg_new, "iv_tweak", json_object_new_uint64(rh->offset >> SECTOR_SHIFT));
		tmp = json_segment_get_size(jobj_seg_new, 0) + rh->length;
	}

	/* alter size of new segment, reenc_seg == 0 we're finished */
	json_object_object_add(jobj_seg_new, "size", reenc_seg > 0 ? json_object_new_uint64(tmp) : json_object_new_string("dynamic"));
	log_dbg("jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_seg_new, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_seg_new);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_enc_create_segments_shift_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int sg, crypt_seg, i = 0;
	uint64_t segment_size;
	json_object *jobj_seg_shrunk, *jobj_enc_seg, *jobj_seg_new, *jobj_copy,
		     *jobj_segs_pre = json_object_new_object();

	if (!jobj_segs_pre)
		return NULL;

	crypt_seg = LUKS2_segment_by_type(hdr, "crypt");

	/* FIXME: This is hack. Find proper way to fix it. */
	sg = LUKS2_last_segment_by_type(hdr, "linear");
	if (rh->offset && sg < 0)
		goto err;
	if (sg < 0)
		return jobj_segs_pre;

	jobj_enc_seg = LUKS2_segment_create_crypt(data_offset + rh->offset,
						      rh->offset >> SECTOR_SHIFT,
						      &rh->length,
						      LUKS2_reencrypt_segment_cipher_new(hdr),
						      LUKS2_reencrypt_get_sector_size_new(hdr),
						      1);
	log_dbg("jobj_enc_seg: %s", json_object_to_json_string_ext(jobj_enc_seg, JSON_C_TO_STRING_PRETTY));

	while (i < sg) {
		jobj_copy = LUKS2_get_segment_jobj(hdr, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, i++, json_object_get(jobj_copy));
	}

	segment_size = LUKS2_segment_size(hdr, sg, 0);
	if (segment_size > rh->length) {
		jobj_seg_shrunk = NULL;
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, sg), &jobj_seg_shrunk))
			goto err;
		json_object_object_add(jobj_seg_shrunk, "size", json_object_new_uint64(segment_size - rh->length));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_seg_shrunk);
		log_dbg("jobj_seg_shrunk: %s", json_object_to_json_string_ext(jobj_seg_shrunk, JSON_C_TO_STRING_PRETTY));
	}

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_enc_seg);
	jobj_enc_seg = NULL; /* see err: label */

	/* first crypt segment after encryption ? */
	if (crypt_seg >= 0) {
		jobj_seg_new = LUKS2_get_segment_jobj(hdr, crypt_seg);
		if (!jobj_seg_new)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, sg, json_object_get(jobj_seg_new));
		log_dbg("jobj_seg_new: %s", json_object_to_json_string_ext(jobj_seg_new, JSON_C_TO_STRING_PRETTY));
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_enc_seg);
	json_object_put(jobj_segs_pre);

	return NULL;
}

static json_object *_enc_create_segments_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size,
	uint64_t data_offset)
{
	json_object *jobj_enc_seg, *jobj_old_seg, *jobj_new_seg,
		    *jobj_segs_pre = json_object_new_object();
	int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		jobj_new_seg = LUKS2_segment_create_crypt(data_offset,
						    crypt_get_iv_offset(cd),
						    &rh->offset,
						    LUKS2_reencrypt_segment_cipher_new(hdr),
						    LUKS2_reencrypt_get_sector_size_new(hdr),
						    0);
		if (!jobj_new_seg)
			goto err;
		log_dbg("jobj_new_seg: %s", json_object_to_json_string_ext(jobj_new_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_new_seg);
	}

	jobj_enc_seg = LUKS2_segment_create_crypt(data_offset + rh->offset,
					      crypt_get_iv_offset(cd) + (rh->offset >> SECTOR_SHIFT),
					      &rh->length, LUKS2_reencrypt_segment_cipher_new(hdr),
					      LUKS2_reencrypt_get_sector_size_new(hdr),
					      1);
	if (!jobj_enc_seg)
		goto err;

	log_dbg("jobj_enc_seg: %s", json_object_to_json_string_ext(jobj_enc_seg, JSON_C_TO_STRING_PRETTY));

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_enc_seg);

	if (tmp < device_size) {
		jobj_old_seg = LUKS2_segment_create_linear(data_offset + tmp, NULL, 0);
		if (!jobj_old_seg)
			goto err;
		log_dbg("jobj_old_seg: %s", json_object_to_json_string_ext(jobj_old_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_old_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static json_object *_LUKS2_reenc_create_segments_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();
	uint64_t tmp = rh->offset + rh->length;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1);

	/*
	 * if there's no old segment after reencryption, we're done.
	 * Set size to 'dynamic' again.
	 */
	jobj_new_seg_after = LUKS2_segment_create_crypt(
					    data_offset,
					    crypt_get_iv_offset(cd),
					    jobj_old_seg ? &tmp : NULL,
					    LUKS2_reencrypt_segment_cipher_new(hdr),
					    LUKS2_reencrypt_get_sector_size_new(hdr),
					    0);
	if (!jobj_new_seg_after)
		goto err;
	log_dbg("jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_new_seg_after, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, 0, jobj_new_seg_after);

	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, 1, json_object_get(jobj_old_seg));

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_LUKS2_enc_create_segments_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size,
	uint64_t data_offset)
{
	if (rh->rp.type == REENC_PROTECTION_DATASHIFT)
		return _enc_create_segments_shift_pre(cd, hdr, rh, data_offset);
	else
		return _enc_create_segments_pre(cd, hdr, rh, device_size, data_offset);
}

static json_object *_LUKS2_enc_create_segments_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	if (rh->rp.type == REENC_PROTECTION_DATASHIFT)
		return _enc_create_segments_shift_after(cd, hdr, rh, data_offset);
	else
		return _LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset);
}

static json_object *_LUKS2_dec_create_segments_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size,
	uint64_t data_offset)
{
	json_object *jobj_dec_seg, *jobj_new_seg, *jobj_old_seg = NULL,
		    *jobj_segs_pre = json_object_new_object();
	int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_old_seg))
			goto err;

		json_object_object_add(jobj_old_seg, "size", json_object_new_uint64(rh->offset));
		log_dbg("jobj_old_seg: %s", json_object_to_json_string_ext(jobj_old_seg, JSON_C_TO_STRING_PRETTY));

		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_old_seg);
	}

	jobj_dec_seg = LUKS2_segment_create_linear(data_offset + rh->offset, &rh->length, 1);
	if (!jobj_dec_seg)
		goto err;
	json_object_object_add(jobj_dec_seg, "iv_tweak", json_object_new_uint64(crypt_get_iv_offset(cd) + (rh->offset >> SECTOR_SHIFT)));

	log_dbg("jobj_dec_seg: %s", json_object_to_json_string_ext(jobj_dec_seg, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_dec_seg);

	if (tmp < device_size) {
		jobj_new_seg = LUKS2_segment_create_linear(data_offset + tmp, NULL, 0);
		if (!jobj_new_seg)
			goto err;
		log_dbg("jobj_new_seg: %s", json_object_to_json_string_ext(jobj_new_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_new_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static json_object *_LUKS2_dec_create_segments_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg - 1);
	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, reenc_seg - 1, json_object_get(jobj_old_seg));
	jobj_new_seg_after = LUKS2_segment_create_linear(data_offset + rh->offset, NULL, 0);
	if (!jobj_new_seg_after)
		goto err;
	log_dbg("jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_new_seg_after, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_new_seg_after);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_LUKS2_reenc_create_segments_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t device_size,
	uint64_t data_offset)
{
	unsigned int sg = 0;
	json_object *jobj_segs_pre, *jobj_reenc_seg, *jobj_old_seg, *jobj_new_seg;
	uint64_t tmp = rh->offset + rh->length;

	jobj_segs_pre = json_object_new_object();
	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		jobj_new_seg = LUKS2_segment_create_crypt(data_offset,
						    crypt_get_iv_offset(cd),
						    &rh->offset,
						    LUKS2_reencrypt_segment_cipher_new(hdr),
						    LUKS2_reencrypt_get_sector_size_new(hdr),
						    0);
		if (!jobj_new_seg)
			goto err;
		log_dbg("jobj_new_seg: %s", json_object_to_json_string_ext(jobj_new_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_new_seg);
	}

	jobj_reenc_seg = LUKS2_segment_create_crypt(data_offset + rh->offset,
					      crypt_get_iv_offset(cd) + (rh->offset >> SECTOR_SHIFT),
					      &rh->length, LUKS2_reencrypt_segment_cipher_new(hdr),
					      LUKS2_reencrypt_get_sector_size_new(hdr),
					      1);
	if (!jobj_reenc_seg)
		goto err;

	log_dbg("jobj_reenc_seg: %s", json_object_to_json_string_ext(jobj_reenc_seg, JSON_C_TO_STRING_PRETTY));

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_reenc_seg);

	if (tmp < device_size) {
		jobj_old_seg = LUKS2_segment_create_crypt(data_offset + tmp,
						    crypt_get_iv_offset(cd) + (tmp >> SECTOR_SHIFT),
						    NULL,
						    LUKS2_reencrypt_segment_cipher_old(hdr),
						    LUKS2_reencrypt_get_sector_size_old(hdr),
						    0);
		if (!jobj_old_seg)
			goto err;
		log_dbg("jobj_old_seg: %s", json_object_to_json_string_ext(jobj_old_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_old_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static int LUKS2_reenc_create_segments_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	rh->jobj_segs_pre = NULL;

	switch (rh->type) {
	case REENCRYPT:
		log_dbg("Calculating hot segments for reencryption.");
		rh->jobj_segs_pre = _LUKS2_reenc_create_segments_pre(cd, hdr, rh, device_size, data_offset);
		break;
	case ENCRYPT:
		log_dbg("Calculating hot segments for encryption.");
		rh->jobj_segs_pre = _LUKS2_enc_create_segments_pre(cd, hdr, rh, device_size, data_offset);
		break;
	case DECRYPT:
		if (rh->data_shift) /* not implemented */
			return -ENOTSUP;
		log_dbg("Calculating hot segments for decryption.");
		rh->jobj_segs_pre = _LUKS2_dec_create_segments_pre(cd, hdr, rh, device_size, data_offset);
		break;
	default:
		return -ENOTSUP;
	}

	return rh->jobj_segs_pre ? 0 : -EINVAL;
}

int LUKS2_reenc_create_segments_after(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t data_offset)
{
	rh->jobj_segs_after = NULL;

	switch (rh->type) {
	case REENCRYPT:
		log_dbg("Calculating segments after reencryption.");
		rh->jobj_segs_after = _LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset);
		break;
	case ENCRYPT:
		log_dbg("Calculating segments after encryption.");
		rh->jobj_segs_after = _LUKS2_enc_create_segments_after(cd, hdr, rh, data_offset);
		break;
	case DECRYPT:
		if (rh->data_shift) /* not implemented */
			return -ENOTSUP;
		log_dbg("Calculating segments after decryption.");
		rh->jobj_segs_after = _LUKS2_dec_create_segments_after(cd, hdr, rh, data_offset);
		break;
	default:
		return -ENOTSUP;
	}

	return rh->jobj_segs_after ? 0 : -EINVAL;
}

int LUKS2_reenc_create_segments(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh,
				uint64_t device_size)
{
	int r;
	uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;

	if ((r = LUKS2_reenc_create_segments_pre(cd, hdr, rh, device_size, data_offset)))
		return r;

	if ((r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset)))
		json_object_put(rh->jobj_segs_pre);

	return r;
}

int64_t LUKS2_reencrypt_data_shift(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_data_shift;
	int ks = LUKS2_find_keyslot(NULL, hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "data_shift", &jobj_data_shift))
		return 0;

	return json_object_get_int64_ex(jobj_data_shift);
}

const char *LUKS2_reencrypt_mode(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_mode;
	int ks = LUKS2_find_keyslot(NULL, hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);
	json_object_object_get_ex(jobj_keyslot, "mode", &jobj_mode);

	return json_object_get_string(jobj_mode);
}
