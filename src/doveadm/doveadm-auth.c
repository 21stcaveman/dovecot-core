/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "askpass.h"
#include "base64.h"
#include "hex-binary.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "wildcard-match.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "auth-client.h"
#include "auth-master.h"
#include "master-auth.h"
#include "master-login-auth.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

static struct event_category event_category_auth = {
	.name = "auth",
};

struct authtest_input {
	pool_t pool;
	const char *username;
	const char *master_user;
	const char *password;
	struct auth_user_info info;
	bool success;

	struct auth_client_request *request;
	struct master_auth_request master_auth_req;

	unsigned int auth_id;
	unsigned int auth_pid;
	const char *auth_cookie;

};

static bool auth_want_log_debug(void)
{
	struct event *event_auth = event_create(NULL);
	event_add_category(event_auth, &event_category_auth);

	bool ret = doveadm_debug || doveadm_settings->auth_debug ||
		event_want_debug_log(event_auth);

	event_unref(&event_auth);

	return ret;
}

static void auth_cmd_help(struct doveadm_cmd_context *cctx);

static struct auth_master_connection *
doveadm_get_auth_master_conn(const char *auth_socket_path)
{
	enum auth_master_flags flags = 0;

	if (auth_want_log_debug())
		flags |= AUTH_MASTER_FLAG_DEBUG;
	return auth_master_init(auth_socket_path, flags);
}

static int
cmd_user_input(struct auth_master_connection *conn,
	       const struct authtest_input *input,
	       const char *show_field, bool userdb)
{
	const char *lookup_name = userdb ? "userdb lookup" : "passdb lookup";
	pool_t pool;
	const char *updated_username = NULL, *const *fields, *p;
	int ret;

	pool = pool_alloconly_create("auth master lookup", 1024);

	if (userdb) {
		ret = auth_master_user_lookup(conn, input->username, &input->info,
					      pool, &updated_username, &fields);
	} else {
		ret = auth_master_pass_lookup(conn, input->username, &input->info,
					      pool, &fields);
	}
	if (ret < 0) {
		if (fields[0] == NULL)
			i_error("%s failed for %s", lookup_name, input->username);
		else {
			i_error("%s failed for %s: %s", lookup_name,
				input->username, fields[0]);
		}
		ret = -1;
	} else if (ret == 0) {
		fprintf(show_field == NULL ? stdout : stderr,
			"%s: user %s doesn't exist\n", lookup_name,
			input->username);
	} else if (show_field != NULL) {
		size_t show_field_len = strlen(show_field);

		for (; *fields != NULL; fields++) {
			if (strncmp(*fields, show_field, show_field_len) == 0 &&
			    (*fields)[show_field_len] == '=')
				printf("%s\n", *fields + show_field_len + 1);
		}
	} else {
		printf("%s: %s\n", userdb ? "userdb" : "passdb", input->username);

		if (updated_username != NULL)
			printf("  %-10s: %s\n", "user", updated_username);
		for (; *fields != NULL; fields++) {
			p = strchr(*fields, '=');
			if (p == NULL)
				printf("  %-10s\n", *fields);
			else {
				printf("  %-10s: %s\n",
				       t_strcut(*fields, '='), p + 1);
			}
		}
	}
	pool_unref(&pool);
	return ret;
}

static void
auth_callback(struct auth_client_request *request ATTR_UNUSED,
	      enum auth_request_status status,
	      const char *data_base64 ATTR_UNUSED,
	      const char *const *args, void *context)
{
	struct authtest_input *input = context;

	input->request = NULL;
	input->auth_id = auth_client_request_get_id(request);
	input->auth_pid = auth_client_request_get_server_pid(request);
	input->auth_cookie = input->pool == NULL ? NULL :
		p_strdup(input->pool, auth_client_request_get_cookie(request));

	if (!io_loop_is_running(current_ioloop))
		return;

	if (status == 0)
		i_fatal("passdb expects SASL continuation");

	switch (status) {
	case AUTH_REQUEST_STATUS_ABORT:
		i_unreached();
	case AUTH_REQUEST_STATUS_INTERNAL_FAIL:
	case AUTH_REQUEST_STATUS_FAIL:
		printf("passdb: %s auth failed\n", input->username);
		break;
	case AUTH_REQUEST_STATUS_CONTINUE:
		printf("passdb: %s auth unexpectedly requested continuation\n",
		       input->username);
		break;
	case AUTH_REQUEST_STATUS_OK:
		input->success = TRUE;
		printf("passdb: %s auth succeeded\n", input->username);
		break;
	}

	if (args != NULL && *args != NULL) {
		printf("extra fields:\n");
		for (; *args != NULL; args++)
			printf("  %s\n", *args);
	}
	io_loop_stop(current_ioloop);
}

static void auth_connected(struct auth_client *client,
			   bool connected, void *context)
{
	struct authtest_input *input = context;
	struct auth_request_info info;
	string_t *init_resp, *base64_resp;

	if (!connected)
		i_fatal("Couldn't connect to auth socket");

	init_resp = t_str_new(128);
	str_append(init_resp, input->username);
	str_append_c(init_resp, '\0');
	if (input->master_user != NULL)
		str_append(init_resp, input->master_user);
	else
		str_append(init_resp, input->username);
	str_append_c(init_resp, '\0');
	str_append(init_resp, input->password);

	base64_resp = t_str_new(128);
	base64_encode(str_data(init_resp), str_len(init_resp), base64_resp);

	i_zero(&info);
	info.mech = "PLAIN";
	info.service = input->info.service;
	info.session_id = input->info.session_id;
	info.local_name = input->info.local_name;
	info.local_ip = input->info.local_ip;
	info.local_port = input->info.local_port;
	info.remote_ip = input->info.remote_ip;
	info.remote_port = input->info.remote_port;
	info.real_local_ip = input->info.real_local_ip;
	info.real_remote_ip = input->info.real_remote_ip;
	info.real_local_port = input->info.real_local_port;
	info.real_remote_port = input->info.real_remote_port;
	info.extra_fields = input->info.extra_fields;
	info.forward_fields = input->info.forward_fields;
	info.initial_resp_base64 = str_c(base64_resp);
	if (auth_want_log_debug())
		info.flags |= AUTH_REQUEST_FLAG_DEBUG;

	input->request = auth_client_request_new(client, &info,
						 auth_callback, input);
}

static void
cmd_auth_input(const char *auth_socket_path, struct authtest_input *input)
{
	struct auth_client *client;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-client", NULL);
	}

	client = auth_client_init(auth_socket_path, getpid(), FALSE);
	auth_client_connect(client);
	auth_client_set_connect_notify(client, auth_connected, input);

	if (!auth_client_is_disconnected(client))
		io_loop_run(current_ioloop);

	auth_client_set_connect_notify(client, NULL, NULL);
	auth_client_deinit(&client);
}

static void
auth_user_info_parse_arg(struct auth_user_info *info, const char *arg)
{
	const char *key, *value;

	if (str_begins(arg, "service=", &value))
		info->service = value;
	else if (str_begins(arg, "session=", &value))
		info->session_id = value;
	else if (str_begins(arg, "local_name=", &value))
		info->local_name = value;
	else if (str_begins(arg, "lip=", &value)) {
		if (net_addr2ip(value, &info->local_ip) < 0)
			i_fatal("lip: Invalid ip");
	} else if (str_begins(arg, "rip=", &value)) {
		if (net_addr2ip(value, &info->remote_ip) < 0)
			i_fatal("rip: Invalid ip");
	} else if (str_begins(arg, "lport=", &value)) {
		if (net_str2port(value, &info->local_port) < 0)
			i_fatal("lport: Invalid port number");
	} else if (str_begins(arg, "rport=", &value)) {
		if (net_str2port(value, &info->remote_port) < 0)
			i_fatal("rport: Invalid port number");
	} else if (str_begins(arg, "real_lip=", &value)) {
		if (net_addr2ip(value, &info->real_local_ip) < 0)
			i_fatal("real_lip: Invalid ip");
	} else if (str_begins(arg, "real_rip=", &value)) {
		if (net_addr2ip(value, &info->real_remote_ip) < 0)
			i_fatal("real_rip: Invalid ip");
	} else if (str_begins(arg, "real_lport=", &value)) {
		if (net_str2port(value, &info->real_local_port) < 0)
			i_fatal("real_lport: Invalid port number");
	} else if (str_begins(arg, "real_rport=", &value)) {
		if (net_str2port(value, &info->real_remote_port) < 0)
			i_fatal("real_rport: Invalid port number");
	} else if (str_begins(arg, "forward_", &key)) {
		value = strchr(key, '=');

		if (value == NULL)
			value = "";
		else
			key = t_strdup_until(key, value++);
		key = str_tabescape(key);
		value = str_tabescape(value);
		if (info->forward_fields == NULL) {
			info->forward_fields =
				t_strdup_printf("%s=%s", key, value);
		} else {
			info->forward_fields =
				t_strdup_printf("%s\t%s=%s", info->forward_fields, key, value);
		}
	} else {
		if (!array_is_created(&info->extra_fields))
			t_array_init(&info->extra_fields, 4);
		array_push_back(&info->extra_fields, &arg);
	}
}

static void
auth_user_info_parse(struct auth_user_info *info, const char *const *args)
{
	for (unsigned int i = 0; args[i] != NULL; i++)
		auth_user_info_parse_arg(info, args[i]);
}

static void
cmd_user_list(struct auth_master_connection *conn,
	      const struct authtest_input *input,
	      const char *const *users)
{
	struct auth_master_user_list_ctx *ctx;
	const char *username, *user_mask = "*";
	unsigned int i;

	if (users[0] != NULL && users[1] == NULL)
		user_mask = users[0];

	ctx = auth_master_user_list_init(conn, user_mask, &input->info);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		for (i = 0; users[i] != NULL; i++) {
			if (wildcard_match_icase(username, users[i]))
				break;
		}
		if (users[i] != NULL)
			printf("%s\n", username);
	}
	if (auth_master_user_list_deinit(&ctx) < 0)
		i_fatal("user listing failed");
}

static void cmd_auth_cache_flush(struct doveadm_cmd_context *cctx)
{
	const char *master_socket_path;
	struct auth_master_connection *conn;
	const char *const *users = NULL;
	unsigned int count;

	if (!doveadm_cmd_param_str(cctx, "socket-path", &master_socket_path)) {
		master_socket_path = t_strconcat(doveadm_settings->base_dir,
						 "/auth-master", NULL);
	}
	(void)doveadm_cmd_param_array(cctx, "user", &users);

	conn = doveadm_get_auth_master_conn(master_socket_path);
	if (auth_master_cache_flush(conn, users, &count) < 0) {
		i_error("Cache flush failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else {
		printf("%u cache entries flushed\n", count);
	}
	auth_master_deinit(&conn);
}

static void authtest_input_init(struct authtest_input *input)
{
	i_zero(input);
	input->info.service = "doveadm";
	input->info.debug = auth_want_log_debug();
}

static void cmd_auth_test(struct doveadm_cmd_context *cctx)
{
	const char *auth_socket_path = NULL;
	const char *const *auth_info;
	struct authtest_input input;

	authtest_input_init(&input);
	(void)doveadm_cmd_param_str(cctx, "socket-path", &auth_socket_path);
	(void)doveadm_cmd_param_str(cctx, "master-user", &input.master_user);
	if (doveadm_cmd_param_array(cctx, "auth-info", &auth_info))
		auth_user_info_parse(&input.info, auth_info);

	if (!doveadm_cmd_param_str(cctx, "user", &input.username))
		auth_cmd_help(cctx);
	if (!doveadm_cmd_param_str(cctx, "password", &input.password))
		input.password = t_askpass("Password: ");
	cmd_auth_input(auth_socket_path, &input);
	if (!input.success)
		doveadm_exit_code = EX_NOPERM;
}

static void
master_auth_callback(const char *const *auth_args,
		     const char *errormsg, void *context)
{
	struct authtest_input *input = context;
	unsigned int i;

	io_loop_stop(current_ioloop);
	if (errormsg != NULL) {
		i_error("userdb lookup failed: %s", errormsg);
		return;
	}
	printf("userdb extra fields:\n");
	for (i = 0; auth_args[i] != NULL; i++)
		printf("  %s\n", auth_args[i]);
	input->success = TRUE;
}

static void
cmd_auth_master_input(const char *auth_master_socket_path,
		      struct authtest_input *input)
{
	struct master_login_auth *master_auth;
	struct master_auth_request master_auth_req;
	buffer_t buf;

	i_zero(&master_auth_req);
	master_auth_req.tag = 1;
	master_auth_req.auth_pid = input->auth_pid;
	master_auth_req.auth_id = input->auth_id;
	master_auth_req.client_pid = getpid();
	master_auth_req.local_ip = input->info.local_ip;
	master_auth_req.remote_ip = input->info.remote_ip;

	buffer_create_from_data(&buf, master_auth_req.cookie,
				sizeof(master_auth_req.cookie));
	if (strlen(input->auth_cookie) == MASTER_AUTH_COOKIE_SIZE*2)
		(void)hex_to_binary(input->auth_cookie, &buf);

	input->success = FALSE;
	master_auth = master_login_auth_init(auth_master_socket_path, FALSE);
	io_loop_set_running(current_ioloop);
	master_login_auth_request(master_auth, &master_auth_req,
				  master_auth_callback, input);
	if (io_loop_is_running(current_ioloop))
		io_loop_run(current_ioloop);
	master_login_auth_deinit(&master_auth);
}

static void cmd_auth_login(struct doveadm_cmd_context *cctx)
{
	const char *auth_login_socket_path, *auth_master_socket_path;
	const char *const *auth_info;
	struct auth_client *auth_client;
	struct authtest_input input;

	authtest_input_init(&input);
	if (!doveadm_cmd_param_str(cctx, "auth-login-socket-path",
				   &auth_login_socket_path)) {
		auth_login_socket_path =
			t_strconcat(doveadm_settings->base_dir,
				    "/auth-login", NULL);
	}
	if (!doveadm_cmd_param_str(cctx, "auth-master-socket-path",
				   &auth_master_socket_path)) {
		auth_master_socket_path =
			t_strconcat(doveadm_settings->base_dir,
				    "/auth-master", NULL);
	}
	(void)doveadm_cmd_param_str(cctx, "master-user", &input.master_user);
	if (doveadm_cmd_param_array(cctx, "auth-info", &auth_info))
		auth_user_info_parse(&input.info, auth_info);
	if (!doveadm_cmd_param_str(cctx, "user", &input.username))
		auth_cmd_help(cctx);
	if (!doveadm_cmd_param_str(cctx, "password", &input.password))
		input.password = t_askpass("Password: ");

	input.pool = pool_alloconly_create("auth login", 256);
	/* authenticate */
	auth_client = auth_client_init(auth_login_socket_path, getpid(), FALSE);
	auth_client_connect(auth_client);
	auth_client_set_connect_notify(auth_client, auth_connected, &input);
	if (!auth_client_is_disconnected(auth_client))
		io_loop_run(current_ioloop);
	auth_client_set_connect_notify(auth_client, NULL, NULL);
	/* finish login with userdb lookup */
	if (input.success)
		cmd_auth_master_input(auth_master_socket_path, &input);
	if (!input.success)
		doveadm_exit_code = EX_NOPERM;
	auth_client_deinit(&auth_client);
	pool_unref(&input.pool);
}

static void cmd_auth_lookup(struct doveadm_cmd_context *cctx)
{
	const char *auth_socket_path;
	struct auth_master_connection *conn;
	struct authtest_input input;
	const char *show_field = NULL;
	const char *const *auth_info, *const *users;
	bool first = TRUE;
	int ret;

	authtest_input_init(&input);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &auth_socket_path))
		auth_socket_path = doveadm_settings->auth_socket_path;
	(void)doveadm_cmd_param_str(cctx, "field", &show_field);
	if (doveadm_cmd_param_array(cctx, "auth-info", &auth_info))
		auth_user_info_parse(&input.info, auth_info);
	if (!doveadm_cmd_param_array(cctx, "user", &users))
		auth_cmd_help(cctx);

	conn = doveadm_get_auth_master_conn(auth_socket_path);
	for (unsigned int i = 0; users[i] != NULL; i++) {
		input.username = users[i];
		if (first)
			first = FALSE;
		else
			putchar('\n');

		ret = cmd_user_input(conn, &input, show_field, FALSE);
		switch (ret) {
		case -1:
			doveadm_exit_code = EX_TEMPFAIL;
			break;
		case 0:
			doveadm_exit_code = EX_NOUSER;
			break;
		}
	}
	auth_master_deinit(&conn);
}

static void cmd_user_mail_input_field(const char *key, const char *value,
				      const char *show_field)
{
	if (show_field == NULL) {
		doveadm_print(key);
		doveadm_print(value);
	} else if (strcmp(show_field, key) == 0) {
		printf("%s\n", value);
	}
}

static void
cmd_user_mail_print_fields(const struct authtest_input *input,
			   struct mail_user *user,
			   const char *const *userdb_fields,
			   const char *show_field)
{
	const struct mail_storage_settings *mail_set;
	const char *key, *value;
	unsigned int i;

	if (strcmp(input->username, user->username) != 0)
		cmd_user_mail_input_field("user", user->username, show_field);
	cmd_user_mail_input_field("uid", user->set->mail_uid, show_field);
	cmd_user_mail_input_field("gid", user->set->mail_gid, show_field);
	cmd_user_mail_input_field("home", user->set->mail_home, show_field);

	mail_set = mail_user_set_get_storage_set(user);
	cmd_user_mail_input_field("mail", mail_set->mail_location, show_field);

	if (userdb_fields != NULL) {
		for (i = 0; userdb_fields[i] != NULL; i++) {
			value = strchr(userdb_fields[i], '=');
			if (value != NULL)
				key = t_strdup_until(userdb_fields[i], value++);
			else {
				key = userdb_fields[i];
				value = "";
			}
			if (strcmp(key, "uid") != 0 &&
			    strcmp(key, "gid") != 0 &&
			    strcmp(key, "home") != 0 &&
			    strcmp(key, "mail") != 0)
				cmd_user_mail_input_field(key, value, show_field);
		}
	}
}

static int
cmd_user_mail_input(struct mail_storage_service_ctx *storage_service,
		    const struct authtest_input *input,
		    const char *show_field, const char *expand_field)
{
	struct mail_storage_service_input service_input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *error, *const *userdb_fields;
	pool_t pool;
	int ret;

	i_zero(&service_input);
	service_input.module = "mail";
	service_input.service = input->info.service;
	service_input.username = input->username;
	service_input.local_ip = input->info.local_ip;
	service_input.local_port = input->info.local_port;
	service_input.remote_ip = input->info.remote_ip;
	service_input.remote_port = input->info.remote_port;
	service_input.debug = input->info.debug;

	pool = pool_alloconly_create("userdb fields", 1024);
	mail_storage_service_save_userdb_fields(storage_service, pool,
						&userdb_fields);

	if ((ret = mail_storage_service_lookup_next(storage_service, &service_input,
						    &service_user, &user,
						    &error)) <= 0) {
		pool_unref(&pool);
		if (ret < 0)
			return -1;
		fprintf(show_field == NULL && expand_field == NULL ? stdout : stderr,
			"\nuserdb lookup: user %s doesn't exist\n",
			input->username);
		return 0;
	}

	if (expand_field == NULL)
		cmd_user_mail_print_fields(input, user, userdb_fields, show_field);
	else {
		string_t *str = t_str_new(128);
		if (var_expand_with_funcs(str, expand_field,
					  mail_user_var_expand_table(user),
					  mail_user_var_expand_func_table, user,
					  &error) <= 0) {
			i_error("Failed to expand %s: %s", expand_field, error);
		} else {
			printf("%s\n", str_c(str));
		}
	}

	mail_user_deinit(&user);
	mail_storage_service_user_unref(&service_user);
	pool_unref(&pool);
	return 1;
}

static void cmd_user(struct doveadm_cmd_context *cctx)
{
	const char *auth_socket_path;
	struct auth_master_connection *conn;
	struct authtest_input input;
	const char *show_field = NULL, *expand_field = NULL;
	const char *const *user_masks, *const *auth_info;
	struct mail_storage_service_ctx *storage_service = NULL;
	unsigned int i;
	bool have_wildcards, userdb_only = FALSE, first = TRUE;
	int ret;

	authtest_input_init(&input);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &auth_socket_path))
		auth_socket_path = doveadm_settings->auth_socket_path;
	(void)doveadm_cmd_param_str(cctx, "field", &show_field);
	(void)doveadm_cmd_param_str(cctx, "expand-field", &expand_field);
	(void)doveadm_cmd_param_bool(cctx, "userdb-only", &userdb_only);
	if (doveadm_cmd_param_array(cctx, "auth-info", &auth_info))
		auth_user_info_parse(&input.info, auth_info);
	if (!doveadm_cmd_param_array(cctx, "user-mask", &user_masks))
		auth_cmd_help(cctx);

	if (expand_field != NULL && userdb_only) {
		i_error("-e can't be used with -u");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	if (expand_field != NULL && show_field != NULL) {
		i_error("-e can't be used with -f");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	conn = doveadm_get_auth_master_conn(auth_socket_path);

	have_wildcards = FALSE;
	for (i = 0; user_masks[i] != NULL; i++) {
		if (strchr(user_masks[i], '*') != NULL ||
		    strchr(user_masks[i], '?') != NULL) {
			have_wildcards = TRUE;
			break;
		}
	}

	if (have_wildcards) {
		cmd_user_list(conn, &input, user_masks);
		auth_master_deinit(&conn);
		return;
	}

	if (!userdb_only) {
		storage_service = mail_storage_service_init(master_service, NULL,
			MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
			MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
			MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
			MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS |
			MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES |
			MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS);
		mail_storage_service_set_auth_conn(storage_service, conn);
		conn = NULL;
		if (show_field == NULL && expand_field == NULL) {
			doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
			doveadm_print_header_simple("field");
			doveadm_print_header_simple("value");
		}
	}

	for (i = 0; user_masks[i] != NULL; i++) {
		input.username = user_masks[i];
		if (first)
			first = FALSE;
		else
			putchar('\n');

		ret = !userdb_only ?
			cmd_user_mail_input(storage_service, &input, show_field, expand_field) :
			cmd_user_input(conn, &input, show_field, TRUE);
		switch (ret) {
		case -1:
			doveadm_exit_code = EX_TEMPFAIL;
			break;
		case 0:
			doveadm_exit_code = EX_NOUSER;
			break;
		}
	}
	if (storage_service != NULL)
		mail_storage_service_deinit(&storage_service);
	if (conn != NULL)
		auth_master_deinit(&conn);
}

struct doveadm_cmd_ver2 doveadm_cmd_auth[] = {
{
	.cmd = cmd_auth_test,
	.name = "auth test",
	.usage = "[-a <auth socket path>] [-x <auth info>] [-M <master user>] <user> [<password>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('x', "auth-info", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('M', "master-user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "password", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.cmd = cmd_auth_login,
	.name = "auth login",
	.usage = "[-a <auth-login socket path>] [-m <auth-master socket path>] [-x <auth info>] [-M <master user>] <user> [<password>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "auth-login-socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('m', "auth-master-socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('x', "auth-info", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('M', "master-user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "password", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.cmd = cmd_auth_lookup,
	.name = "auth lookup",
	.usage = "[-a <userdb socket path>] [-x <auth info>] [-f field] <user> [<user> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('x', "auth-info", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('f', "field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.cmd = cmd_auth_cache_flush,
	.name = "auth cache flush",
	.usage = "[-a <master socket path>] [<user> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.cmd = cmd_user,
	.name = "user",
	.usage = "[-a <userdb socket path>] [-x <auth info>] [-f field] [-e <value>] [-u] <user mask> [<user mask> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('x', "auth-info", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('f', "field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('e', "expand-field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('u', "userdb-only", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

static void auth_cmd_help(struct doveadm_cmd_context *cctx)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_auth); i++) {
		if (doveadm_cmd_auth[i].cmd == cctx->cmd->cmd)
			help_ver2(&doveadm_cmd_auth[i]);
	}
	i_unreached();
}

void doveadm_register_auth_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_auth); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_auth[i]);
}
