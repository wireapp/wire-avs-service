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
#include <avs_service.h>
#include <avs_log.h>

static struct {
	char *file;
	char *str;
	struct conf *conf;
} config = {
	.file = NULL,
	.str = NULL,
	.conf = NULL
};
	
void config_set_file(const char *path)
{
	if (!path)
		return;

	config.file = mem_deref(config.file);
	str_dup(&config.file, path);
}

void config_set_buf(const char *str)
{
	if (!str)
		return;

	config.str = mem_deref(config.str);
	str_dup(&config.str, str);
}



int config_init(void)
{
	int err = 0;

	if (config.file) {
		err = conf_alloc(&config.conf, config.file);
		if (err) {
			error("error loading config file %s: %m\n",
			      config.file, err);
		}
	}
	else if (config.str) {
		err = conf_alloc_buf(&config.conf,
				     (const uint8_t *)config.str,
				     str_len(config.str));
		if (err) {
			error("error loading config string %s: %m\n",
			      config.str, err);
		}
	}
	else {
		err = ENOSYS;
	}

	return err;
}


void config_close(void)
{
	config.conf = mem_deref(config.conf);
	config.file = mem_deref(config.file);
	config.str = mem_deref(config.str);
}


struct conf *avs_service_conf(void)
{
	return config.conf;
}
