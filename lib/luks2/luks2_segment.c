/*
 * LUKS - Linux Unified Key Setup v2, internal segment handling
 *
 * Copyright (C) 2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018, Ondrej Kozina. All rights reserved.
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

/* expected valid */
const char *json_segment_type(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "type", &jobj))
		return NULL;

	return json_object_get_string(jobj);
}

uint64_t json_segment_get_offset(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "offset", &jobj))
		return 0;

	return blockwise ? json_object_get_uint64(jobj) >> SECTOR_SHIFT : json_object_get_uint64(jobj);
}

uint64_t json_segment_get_iv_offset(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "iv_tweak", &jobj))
		return 0;

	return json_object_get_uint64(jobj);
}

uint64_t json_segment_get_size(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "size", &jobj))
		return 0;

	return blockwise ? json_object_get_uint64(jobj) >> SECTOR_SHIFT : json_object_get_uint64(jobj);
}

const char *json_segment_get_cipher(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "encryption", &jobj))
		return "null";

	return json_object_get_string(jobj);
}

int json_segment_get_sector_size(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
            !json_object_object_get_ex(jobj_segment, "sector_size", &jobj))
		return -1;

	return json_object_get_int(jobj);
}

int json_segments_count(json_object *jobj_segments)
{
	return !jobj_segments ? -EINVAL : json_object_object_length(jobj_segments);
}

uint64_t json_segments_get_first_data_offset(json_object *jobj_segments, unsigned blockwise)
{
	json_object *jobj;

	/* FIXME this could be fatal. add assert? */
	if (!json_object_object_get_ex(jobj_segments, "0", &jobj))
		return 0;

	return json_segment_get_offset(jobj, blockwise);
}

json_object *json_segments_get_segment(json_object *jobj_segments, int segment)
{
	json_object *jobj;
	char segment_name[16];

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(jobj_segments, segment_name, &jobj))
		return NULL;

	return jobj;
}

uint64_t LUKS2_segment_offset(struct luks2_hdr *hdr, int segment, unsigned blockwise)
{
	return json_segment_get_offset(LUKS2_get_segment_jobj(hdr, segment), blockwise);
}

int json_segments_segment_in_reencrypt(json_object *jobj_segments)
{
	json_object *jobj;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (!json_object_object_get_ex(val, "reencryption", &jobj) ||
		    strcmp("in-progress", json_object_get_string(jobj)))
			continue;

		return atoi(slot);
	}

	return -1;
}

uint64_t LUKS2_segment_size(struct luks2_hdr *hdr, int segment, unsigned blockwise)
{
	return json_segment_get_size(LUKS2_get_segment_jobj(hdr, segment), blockwise);
}

int LUKS2_segment_is_type(struct luks2_hdr *hdr, int segment, const char *type)
{
	return !strcmp(json_segment_type(LUKS2_get_segment_jobj(hdr, segment)) ?: "", type);
}

int LUKS2_last_segment_by_type(struct luks2_hdr *hdr, const char *type)
{
	json_object *jobj_segments;
	int last_found = -1;

	if (!type)
		return -1;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -1;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (strcmp(type, json_segment_type(val) ?: ""))
			continue;

		if (atoi(slot) > last_found)
			last_found = atoi(slot);
	}

	return last_found;
}

int LUKS2_segment_by_type(struct luks2_hdr *hdr, const char *type)
{
	json_object *jobj_segments;
	int first_found = -1;

	if (!type)
		return -1;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -1;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (strcmp(type, json_segment_type(val) ?: ""))
			continue;

		if (first_found < 0)
			first_found = atoi(slot);
		else if (atoi(slot) < first_found)
			first_found = atoi(slot);
	}

	return first_found;
}

static json_object *_segment_create_generic(const char *type, uint64_t offset, uint64_t *length, unsigned reencryption)
{
	json_object *jobj = json_object_new_object();
	if (!jobj)
		return NULL;

	json_object_object_add(jobj, "type",		json_object_new_string(type));
	json_object_object_add(jobj, "offset",		json_object_new_uint64(offset));
	json_object_object_add(jobj, "size",		length ? json_object_new_uint64(*length) : json_object_new_string("dynamic"));
	if (reencryption)
		json_object_object_add(jobj, "reencryption", json_object_new_string("in-progress"));

	return jobj;
}

json_object *LUKS2_segment_create_linear(uint64_t offset, uint64_t *length, unsigned reencryption)
{
	return _segment_create_generic("linear", offset, length, reencryption);
}

json_object *LUKS2_segment_create_crypt(uint64_t offset,
				  uint64_t iv_offset, uint64_t *length,
				  const char *cipher, uint32_t sector_size,
				  unsigned reencryption)
{
	json_object *jobj = _segment_create_generic("crypt", offset, length, reencryption);
	if (!jobj)
		return NULL;

	json_object_object_add(jobj, "iv_tweak",	json_object_new_uint64(iv_offset));
	json_object_object_add(jobj, "encryption",	json_object_new_string(cipher));
	json_object_object_add(jobj, "sector_size",	json_object_new_int(sector_size));

	return jobj;
}

/* FIXME: json-c may already have deep copy fn */
json_object *LUKS2_segment_copy(json_object *jobj_seg)
{
	const char *type;
	json_object *jobj_type, *jobj_copy, *jobj_offset, *jobj_size, *jobj;
	uint64_t tmp;

	if (!jobj_seg)
		return NULL;

	json_object_object_get_ex(jobj_seg, "type", &jobj_type);
	json_object_object_get_ex(jobj_seg, "offset", &jobj_offset);
	json_object_object_get_ex(jobj_seg, "size", &jobj_size);

	type = json_object_get_string(jobj_type);

	tmp = json_object_get_uint64(jobj_size);
	jobj_copy = _segment_create_generic(type,
					    json_object_get_uint64(jobj_offset),
					    tmp ? &tmp : NULL,
					    json_object_object_get_ex(jobj_seg, "reencryption", NULL));
	if (!jobj_copy)
		return NULL;

	if (strcmp(type, "crypt"))
		return jobj_copy;

	json_object_object_get_ex(jobj_seg, "iv_tweak", &jobj);
	json_object_object_add(jobj_copy, "iv_tweak", json_object_new_string(json_object_get_string(jobj)));
	json_object_object_get_ex(jobj_seg, "encryption", &jobj);
	json_object_object_add(jobj_copy, "encryption", json_object_new_string(json_object_get_string(jobj)));
	json_object_object_get_ex(jobj_seg, "sector_size", &jobj);
	json_object_object_add(jobj_copy, "sector_size", json_object_new_int(json_object_get_int(jobj)));

	return jobj_copy;
}

int LUKS2_segments_set(struct crypt_device *cd, struct luks2_hdr *hdr,
		       json_object *jobj_segments, int commit)
{
	json_object_object_add(hdr->jobj, "segments", jobj_segments);

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_segments_count(struct luks2_hdr *hdr)
{
	int count;
	json_object *jobj_segments = NULL;

	json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments);

	count = json_segments_count(jobj_segments);

	return count < 0 ? 0 : count;
}

const char *LUKS2_debug_dump_segments(struct luks2_hdr *hdr)
{
	return json_object_to_json_string_ext(LUKS2_get_segments_jobj(hdr), JSON_C_TO_STRING_PRETTY);
}
