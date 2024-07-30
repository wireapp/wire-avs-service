#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <re.h>

#include "avs_service.h"


int helper_split_paths(char *path, char **parts, int max_parts)
{
	int i = 0;

	if (!path || !(*path))
		return -1;

	do {
		/* Move forward to after slashes */
		while (*path == '/')
			++path;

		if (*path == '\0')
			break;

		parts[i++] = path;

		path = strchr(path, '/');
		if (!path)
			break;

		*(path++) = '\0';
	}
	while (i < max_parts);

	return i;
}

char *helper_make_callid(const char *convid,
			 const char *userid,
			 const char *clientid)
{
	size_t n;
	char *callid;

	n = str_len(convid);
	n += str_len(userid);
	n += str_len(clientid);
	n += 5;

	callid = mem_zalloc(n, NULL);
	if (!callid)
		return NULL;

	re_snprintf(callid, n, "%s.%s.%s", convid, userid, clientid);

	return callid;
}
