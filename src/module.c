/*
* Wire
* Copyright (C) 2016 Wire Swiss GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <re.h>
#include <avs_log.h>
#include <avs_service.h>
#include "score.h"

#ifdef STATIC

extern const struct mod_export *mod_table[];

static const struct mod_export *find_module(const struct pl *name)
{
	uint32_t i;

	for (i=0; mod_table[i]; i++) {
		if (0 == pl_strcasecmp(name, mod_table[i]->name))
			return mod_table[i];
	}

	return NULL;
}


static int module_handler(const struct pl *pl, void *arg)
{
	const struct mod_export *me;
	struct pl name;
	struct mod *m;
	int err;

	(void)arg;

	if (re_regex(pl->p, pl->l, "[^/.]+.[^]*", &name, NULL))
		return EINVAL;

	me = find_module(&name);
	if (!me) {
		error("can't find module %r\n", &name);
		return ENOENT;
	}

	err = mod_add(&m, me);
	if (err) {
		error("can't add module %r: %m\n", &name, err);
		return err;
	}

	return 0;
}

#else

static int module_handler(const struct pl *val, void *arg)
{
	struct pl *modpath = arg;
	char filepath[256];
	struct mod *mod;
	int err;

	if (val->p && val->l && (*val->p == '/'))
		(void)re_snprintf(filepath, sizeof(filepath), "%r", val);
	else
		(void)re_snprintf(filepath, sizeof(filepath), "%r/%r",
				  modpath, val);

	err = mod_load(&mod, filepath);
	if (err) {
		error("module error %s (%m)\n", filepath, err);
		return err;
	}

	return 0;
}

#endif


int module_load(const char *name)
{
	struct pl path = PL(".");
	struct pl pl_name;

	pl_set_str(&pl_name, name);

	return module_handler(&pl_name, &path);
}


int module_init(void)
{
#if 0
	struct pl path;

	if (conf_get(blender_conf(), "module_path", &path))
		pl_set_str(&path, ".");

	return conf_apply(blender_conf(), "module", module_handler, &path);
#endif

	struct pl pl;

	pl_set_str(&pl, "reflow.so");
	module_handler(&pl, NULL);
	
	pl_set_str(&pl, "sft.so");
	module_handler(&pl, NULL);

	
	return 0;
}


void module_close(void)
{
	mod_close();
}
