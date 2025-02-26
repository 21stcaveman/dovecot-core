/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "login-settings.h"
#include "imap-login-settings.h"

#include <stddef.h>

/* <settings checks> */
static struct file_listener_settings imap_login_unix_listeners_array[] = {
	{ "srv.imap-login/%{pid}", 0600, "", "" },
};
static struct file_listener_settings *imap_login_unix_listeners[] = {
	&imap_login_unix_listeners_array[0],
};
static buffer_t imap_login_unix_listeners_buf = {
	{ { imap_login_unix_listeners, sizeof(imap_login_unix_listeners) } }
};

static struct inet_listener_settings imap_login_inet_listeners_array[] = {
	{ .name = "imap", .address = "", .port = 143 },
	{ .name = "imaps", .address = "", .port = 993, .ssl = TRUE }
};
static struct inet_listener_settings *imap_login_inet_listeners[] = {
	&imap_login_inet_listeners_array[0],
	&imap_login_inet_listeners_array[1]
};
static buffer_t imap_login_inet_listeners_buf = {
	{ { imap_login_inet_listeners, sizeof(imap_login_inet_listeners) } }
};
/* </settings checks> */

struct service_settings imap_login_service_settings = {
	.name = "imap-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_login_unix_listeners_buf,
			      sizeof(imap_login_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &imap_login_inet_listeners_buf,
			      sizeof(imap_login_inet_listeners[0]) } }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_login_settings)

static const struct setting_define imap_login_setting_defines[] = {
	DEF(STR, imap_capability),
	DEF(STR, imap_id_send),
	DEF(STR, imap_id_log),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL, imap_id_retain),

	SETTING_DEFINE_LIST_END
};

static const struct imap_login_settings imap_login_default_settings = {
	.imap_capability = "",
	.imap_id_send = "name *",
	.imap_id_log = "",
	.imap_literal_minus = FALSE,
	.imap_id_retain = FALSE,
};

static const struct setting_parser_info *imap_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};

static const struct setting_parser_info imap_login_setting_parser_info = {
	.module_name = "imap-login",
	.defines = imap_login_setting_defines,
	.defaults = &imap_login_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_login_settings),

	.parent_offset = SIZE_MAX,
	.dependencies = imap_login_setting_dependencies
};

const struct setting_parser_info *imap_login_setting_roots[] = {
	&login_setting_parser_info,
	&imap_login_setting_parser_info,
	NULL
};
