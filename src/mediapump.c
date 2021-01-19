/*
 * Wire
 * Copyright (C) 2020 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <re.h>
#include <avs_log.h>
#include <avs_string.h>
#include <stdlib.h>

#include "avs_service.h"

static struct list g_flowl = LIST_INIT;

struct mediapump {
	char *name;
	mediapump_set_handlers_h *set_handlersh;
	mediaflow_send_data_h *send_rtph;
	mediaflow_send_data_h *send_rtcph;
	mediaflow_send_dc_h *send_dch;
	mediaflow_get_ssrc_h *get_ssrch;
	mediaflow_remove_ssrc_h *remove_ssrch;

	struct le le;
};

static void destructor(void *arg)
{
	struct mediapump *mp = arg;

	mem_deref(mp->name);
	list_unlink(&mp->le);
}

static struct mediapump *find_pump(const char *name)
{
	struct le *le;

	LIST_FOREACH(&g_flowl, le) {
		struct mediapump *mp = le->data;
		
		if (streq(name, mp->name))
			return mp;
	}

	return NULL;
}

struct mediapump *mediapump_get(const char *name)
{
	return find_pump(name);
}

int mediapump_set_handlers(struct mediapump *mp,
			   mediaflow_alloc_h *alloch,
			   mediaflow_close_h *closeh,
			   mediaflow_recv_data_h *rtph,
			   mediaflow_recv_data_h *rtcph,
			   mediaflow_recv_dc_h *dch)
{
	if (!mp)
		return EINVAL;

	if (!mp->set_handlersh)
		return ENOSYS;

	mp->set_handlersh(alloch, closeh, rtph, rtcph, dch);

	return 0;
}

int mediaflow_send_rtp(struct mediaflow *mf,
		       const uint8_t *data, size_t len)
{
	struct mediapump *mp;
	int err = ENOSYS;
	
	if (!mf)
		return EINVAL;

	mp = mf->mp;
	if (mp && mp->send_rtph) {
		err = mp->send_rtph(mf, data, len);
	}

	return err;
}

int mediaflow_send_rtcp(struct mediaflow *mf,
			const uint8_t *data, size_t len)
{
	struct mediapump *mp;
	int err = ENOSYS;
	
	if (!mf)
		return EINVAL;

	mp = mf->mp;
	if (mp && mp->send_rtcph) {
		err = mp->send_rtcph(mf, data, len);
	}

	return err;
}

int mediaflow_send_dc(struct mediaflow *mf,
		      const uint8_t *data, size_t len)
{
	struct mediapump *mp;
	int err = ENOSYS;
	
	if (!mf)
		return EINVAL;

	mp = mf->mp;
	if (mp && mp->send_dch) {
		err = mp->send_dch(mf, data, len);
	}

	return err;
}

uint32_t mediaflow_get_ssrc(struct mediaflow *mf, const char *type, bool local)
{
	struct mediapump *mp;
	uint32_t ssrc = 0;
	
	if (!mf)
		return 0;

	mp = mf->mp;
	if (mp && mp->get_ssrch) {
		ssrc = mp->get_ssrch(mf, type, local);
	}

	return ssrc;
}

void mediapump_remove_ssrc(struct mediaflow *mf, uint32_t ssrc)
{
	struct mediapump *mp;

	if (!mf)
		return;

	mp = mf->mp;
	if (mp && mp->remove_ssrch) {
		mp->remove_ssrch(mf, ssrc);
	}
}


int mediapump_register(struct mediapump **mpp,
		       const char *name,
		       mediapump_set_handlers_h *set_handlersh,
		       mediaflow_send_data_h *rtph,
		       mediaflow_send_data_h *rtcph,
		       mediaflow_send_dc_h *dch,
		       mediaflow_get_ssrc_h *get_ssrch,
		       mediaflow_remove_ssrc_h *remove_ssrch)
{
	struct mediapump *mp;

	mp = find_pump(name);
	if (mp) {
		warning("mediaflow_register: mediaflow of type %s "
			"already exists\n", name);
		return EALREADY;
	}

	mp = mem_zalloc(sizeof(*mp), destructor);
	if (!mp)
		return ENOMEM;

	str_dup(&mp->name, name);
	mp->set_handlersh = set_handlersh;
	mp->send_rtph = rtph;
	mp->send_rtcph = rtcph;
	mp->send_dch = dch;
	mp->get_ssrch = get_ssrch;
	mp->remove_ssrch = remove_ssrch;

	list_append(&g_flowl, &mp->le, mp);

	if (mpp)
		*mpp = mp;
	
	return 0;
}

