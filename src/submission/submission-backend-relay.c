/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "str-sanitize.h"
#include "mail-user.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-command.h"

#include "submission-commands.h"
#include "submission-backend-relay.h"

/*
 * Common
 */

/* The command handling of the submission proxy service aims to follow the
   following rules:

   - Attempt to keep pipelined commands pipelined when proxying them to the
     actual relay service.
   - Don't forward commands if they're known to fail at the relay server. Errors
     can still occur if pipelined commands fail. Abort subsequent pending
     commands if such failures affect those commands.
   - Keep predictable errors consistent as much as possible; send our own reply
     if the error condition is clear (e.g. missing MAIL, RCPT).
*/

bool client_command_handle_proxy_reply(struct client *client,
	const struct smtp_reply *reply, struct smtp_reply *reply_r)
{
	*reply_r = *reply;

	switch (reply->status) {
	case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
		i_unreached();
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
	case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
	case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
		client_destroy(client,
			"4.4.0", "Lost connection to relay server");
		return FALSE;
	/* RFC 4954, Section 6: 530 5.7.0 Authentication required

	   This response SHOULD be returned by any command other than AUTH,
	   EHLO, HELO, NOOP, RSET, or QUIT when server policy requires
	   authentication in order to perform the requested action and
	   authentication is not currently in force. */
	case 530:
		i_error("Relay server requires authentication: %s",
			smtp_reply_log(reply));
		client_destroy(client, "4.3.5",
			"Internal error occurred. "
			"Refer to server log for more information.");
		return FALSE;
	default:
		break;
	}

	if (!smtp_reply_has_enhanced_code(reply)) {
		reply_r->enhanced_code =
			SMTP_REPLY_ENH_CODE(reply->status / 100, 0, 0);
	}
	return TRUE;
}

/*
 * EHLO, HELO commands
 */

struct cmd_helo_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_helo *data;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_helo_update_xclient(struct client *client,
				    struct smtp_server_cmd_helo *data)
{
	struct smtp_proxy_data proxy_data;

	if (!client->set->submission_relay_trusted)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = data->helo.domain;
	proxy_data.proto = (data->helo.old_smtp ?
		SMTP_PROXY_PROTOCOL_SMTP : SMTP_PROXY_PROTOCOL_ESMTP);

	(void)smtp_client_connection_send_xclient
		(client->proxy_conn, &proxy_data);
	client->xclient_sent = TRUE;
}

static void
cmd_helo_reply(struct smtp_server_cmd_ctx *cmd, struct cmd_helo_context *helo)
{
	struct client *client = helo->client;

	/* proxy an XCLIENT command */
	if (helo->data->changed)
		cmd_helo_update_xclient(client, helo->data);

	T_BEGIN {
		submission_helo_reply_submit(cmd, helo->data);
	} T_END;
}

static void cmd_helo_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_helo_context *helo)
{
	struct smtp_server_cmd_ctx *cmd = helo->cmd;
	struct client *client = helo->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		cmd_helo_reply(cmd, helo);
	} else {
		/* RFC 2034, Section 4:

		   These codes must appear in all 2xx, 4xx, and 5xx response
		   lines other than initial greeting and any response to HELO
		   or EHLO.
		 */
		reply.enhanced_code = SMTP_REPLY_ENH_CODE_NONE;
		smtp_server_reply_forward(cmd, &reply);
	}
}

static void
cmd_helo_start(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	       struct cmd_helo_context *helo)
{
	struct client *client = helo->client;

	/* proxy an XCLIENT command */
	if (helo->data->changed)
		cmd_helo_update_xclient(client, helo->data);
}

int cmd_helo_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_helo *data)
{
	struct cmd_helo_context *helo;

	helo = p_new(cmd->pool, struct cmd_helo_context, 1);
	helo->client = client;
	helo->cmd = cmd;
	helo->data = data;

	/* this is not the first HELO/EHLO; just proxy a RSET command */
	smtp_server_command_add_hook(
		cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
		cmd_helo_start, helo);
	helo->cmd_proxied = smtp_client_command_rset_submit
		(client->proxy_conn, 0, cmd_helo_proxy_cb, helo);
	return 0;
}

/*
 * MAIL command
 */

struct cmd_mail_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_mail *data;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_mail_update_xclient(struct client *client)
{
	struct smtp_proxy_data proxy_data;
	struct smtp_server_helo_data *helo_data =
		smtp_server_connection_get_helo_data(client->conn);

	if (client->xclient_sent)
		return;
	if (!client->set->submission_relay_trusted)
		return;
	if (helo_data->domain == NULL)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = helo_data->domain;
	proxy_data.proto = SMTP_PROXY_PROTOCOL_ESMTP;

	(void)smtp_client_connection_send_xclient(
		client->proxy_conn, &proxy_data);
	client->xclient_sent = TRUE;
}

static void
cmd_mail_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct cmd_mail_context *mail_cmd)
{
	if (mail_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&mail_cmd->cmd_proxied);
}

static void cmd_mail_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_mail_context *mail_cmd)
{
	struct smtp_server_cmd_ctx *cmd = mail_cmd->cmd;
	struct client *client = mail_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(mail_cmd != NULL);
	mail_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		/* if relay accepts it, we accept it too */

		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 0);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

static int
cmd_mail_parameter_auth(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			enum smtp_capability proxy_caps,
			struct smtp_server_cmd_mail *data)
{
	struct smtp_params_mail *params = &data->params;
	struct smtp_address *auth_addr;
	const char *error;

	if ((proxy_caps & SMTP_CAPABILITY_AUTH) == 0)
		return 0;

	auth_addr = NULL;
	if (smtp_address_parse_username(cmd->pool,
		client->user->username,
		&auth_addr, &error) < 0) {
		i_warning("Username `%s' is not a valid SMTP address: %s",
			client->user->username, error);
	}

	params->auth = auth_addr;
	return 0;
}

static int
cmd_mail_parameter_size(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			enum smtp_capability proxy_caps,
			struct smtp_server_cmd_mail *data)
{
	uoff_t max_size;

	/* SIZE=<size-value>: RFC 1870 */

	if (data->params.size == 0 || (proxy_caps & SMTP_CAPABILITY_SIZE) == 0)
		return 0;

	/* determine actual size limit (account for our additions) */
	max_size = client_get_max_mail_size(client);
	if (max_size > 0 && data->params.size > max_size) {
		smtp_server_reply(cmd, 552, "5.3.4",
			"Message size exceeds fixed maximum message size");
		return -1;
	}

	/* proxy the SIZE parameter (account for additional size) */
	data->params.size += SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE;
	return 0;
}

int cmd_mail_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_mail *data)
{
	struct cmd_mail_context *mail_cmd;
	enum smtp_capability proxy_caps =
		smtp_client_connection_get_capabilities(client->proxy_conn);

	/* check and adjust parameters where necessary */
	if (cmd_mail_parameter_auth(client, cmd, proxy_caps, data) < 0)
		return -1;
	if (cmd_mail_parameter_size(client, cmd, proxy_caps, data) < 0)
		return -1;

	cmd_mail_update_xclient(client);

	/* queue command (pipeline) */
	mail_cmd = p_new(cmd->pool, struct cmd_mail_context, 1);
	mail_cmd->cmd = cmd;
	mail_cmd->data = data;
	mail_cmd->client = client;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     cmd_mail_replied, mail_cmd);

	mail_cmd->cmd_proxied = smtp_client_command_mail_submit(
		client->proxy_conn, 0, data->path, &data->params,
		cmd_mail_proxy_cb, mail_cmd);
	return 0;
}

/*
 * RCPT command
 */

struct cmd_rcpt_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_rcpt *data;

	struct smtp_client_command *cmd_proxied;
};

static void
cmd_rcpt_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct cmd_rcpt_context *rcpt_cmd)
{
	if (rcpt_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&rcpt_cmd->cmd_proxied);
}

static void cmd_rcpt_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_rcpt_context *rcpt_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rcpt_cmd->cmd;
	struct client *client = rcpt_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(rcpt_cmd != NULL);
	rcpt_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 5);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

int cmd_rcpt_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_rcpt *data)
{
	struct cmd_rcpt_context *rcpt_cmd;

	/* queue command (pipeline) */
	rcpt_cmd = p_new(cmd->pool, struct cmd_rcpt_context, 1);
	rcpt_cmd->cmd = cmd;
	rcpt_cmd->data = data;
	rcpt_cmd->client = client;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     cmd_rcpt_replied, rcpt_cmd);

	rcpt_cmd->cmd_proxied = smtp_client_command_rcpt_submit(
		client->proxy_conn, 0, data->path, &data->params,
		cmd_rcpt_proxy_cb, rcpt_cmd);
	return 0;
}

/*
 * RSET command
 */

struct cmd_rset_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_rset_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_rset_context *rset_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rset_cmd->cmd;
	struct client *client = rset_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(rset_cmd != NULL);
	rset_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

int cmd_rset_relay(struct client *client, struct smtp_server_cmd_ctx *cmd)
{
	struct cmd_rset_context *rset_cmd;

	rset_cmd = p_new(cmd->pool, struct cmd_rset_context, 1);
	rset_cmd->cmd = cmd;
	rset_cmd->client = client;

	rset_cmd->cmd_proxied = smtp_client_command_rset_submit
		(client->proxy_conn, 0, cmd_rset_proxy_cb, rset_cmd);
	return 0;
}

/*
 * DATA/BDAT commands
 */

struct cmd_data_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_transaction *trans;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_data_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_data_context *data_ctx)
{
	struct smtp_server_cmd_ctx *cmd = data_ctx->cmd;
	struct smtp_server_transaction *trans = data_ctx->trans;
	struct client *client = data_ctx->client;
	struct smtp_reply reply;

	/* finished proxying message to relay server */

	/* check for fatal problems */
	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if (proxy_reply->status / 100 == 2) {
		i_info("Successfully relayed message: "
		       "from=<%s>, size=%"PRIuUOFF_T", "
		       "id=%s, nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, trans->id,
		       array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(proxy_reply), 128));

	} else {
		i_info("Failed to relay message: "
		       "from=<%s>, size=%"PRIuUOFF_T", nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(proxy_reply), 128));
	}

	smtp_server_reply_forward(cmd, &reply);
}

int cmd_data_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input)
{
	struct cmd_data_context *data_ctx;

	/* start relaying to relay server */
	data_ctx = p_new(trans->pool, struct cmd_data_context, 1);
	data_ctx->client = client;
	data_ctx->cmd = cmd;
	data_ctx->trans = trans;
	trans->context = (void*)data_ctx;

	data_ctx->cmd_proxied = smtp_client_command_data_submit(
		client->proxy_conn, 0, data_input, cmd_data_proxy_cb, data_ctx);
	return 0;
}

/*
 * VRFY command
 */

struct cmd_vrfy_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_vrfy_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_vrfy_context *vrfy_cmd)
{
	struct smtp_server_cmd_ctx *cmd = vrfy_cmd->cmd;
	struct client *client = vrfy_cmd->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if (!smtp_reply_has_enhanced_code(proxy_reply)) {
		switch (proxy_reply->status) {
		case 250:
		case 251:
		case 252:
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 5, 0);
			break;
		default:
			break;
		}
	}

	smtp_server_reply_forward(cmd, &reply);
}

int cmd_vrfy_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   const char *param)
{
	struct cmd_vrfy_context *vrfy_cmd;

	vrfy_cmd = p_new(cmd->pool, struct cmd_vrfy_context, 1);
	vrfy_cmd->client = client;
	vrfy_cmd->cmd = cmd;

	vrfy_cmd->cmd_proxied = smtp_client_command_vrfy_submit(
		client->proxy_conn, 0, param, cmd_vrfy_proxy_cb, vrfy_cmd);
	return 0;
}

/*
 * NOOP command
 */

struct cmd_noop_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_noop_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_noop_context *noop_cmd)
{
	struct smtp_server_cmd_ctx *cmd = noop_cmd->cmd;
	struct client *client = noop_cmd->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		smtp_server_reply(cmd, 250, "2.0.0", "OK");
	} else {
		smtp_server_reply_forward(cmd, &reply);
	}
}

int cmd_noop_relay(struct client *client, struct smtp_server_cmd_ctx *cmd)
{
	struct cmd_noop_context *noop_cmd;

	noop_cmd = p_new(cmd->pool, struct cmd_noop_context, 1);
	noop_cmd->client = client;
	noop_cmd->cmd = cmd;

	noop_cmd->cmd_proxied = smtp_client_command_noop_submit
		(client->proxy_conn, 0, cmd_noop_proxy_cb, noop_cmd);
	return 0;
}

/*
 * QUIT command
 */

struct relay_cmd_quit_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void
relay_cmd_quit_destroy(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_quit_context *quit_cmd)
{
	if (quit_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_proxied);
}

static void
relay_cmd_quit_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_quit_context *quit_cmd)
{
	if (quit_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_proxied);
}

static void relay_cmd_quit_finish(struct relay_cmd_quit_context *quit_cmd)
{
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	if (quit_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_proxied);
	smtp_server_reply_quit(cmd);
}

static void
relay_cmd_quit_proxy_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
			struct relay_cmd_quit_context *quit_cmd)
{
	quit_cmd->cmd_proxied = NULL;
	relay_cmd_quit_finish(quit_cmd);
}

static void relay_cmd_quit_proxy(struct relay_cmd_quit_context *quit_cmd)
{
	struct client *client = quit_cmd->client;
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	if (quit_cmd->cmd_proxied != NULL)
		return;

	if (smtp_client_connection_get_state(client->proxy_conn)
		< SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* Don't bother proxying QUIT command when proxy is not
		   fully initialized. */
		smtp_server_reply_quit(cmd);
		return;
	}

	/* RFC 5321, Section 4.1.1.10:

	   The sender MUST NOT intentionally close the transmission channel
	   until it sends a QUIT command, and it SHOULD wait until it receives
	   the reply (even if there was an error response to a previous
	   command). */
	quit_cmd->cmd_proxied =
		smtp_client_command_new(client->proxy_conn, 0,
					relay_cmd_quit_proxy_cb, quit_cmd);
	smtp_client_command_write(quit_cmd->cmd_proxied, "QUIT");
	smtp_client_command_submit(quit_cmd->cmd_proxied);
}

static void
relay_cmd_quit_next(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		    struct relay_cmd_quit_context *quit_cmd)
{
	/* QUIT command is next to reply */
	relay_cmd_quit_proxy(quit_cmd);
}

int cmd_quit_relay(struct client *client, struct smtp_server_cmd_ctx *cmd)
{
	struct relay_cmd_quit_context *quit_cmd;

	quit_cmd = p_new(cmd->pool, struct relay_cmd_quit_context, 1);
	quit_cmd->client = client;
	quit_cmd->cmd = cmd;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     relay_cmd_quit_next, quit_cmd);
	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     relay_cmd_quit_replied, quit_cmd);
	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     relay_cmd_quit_destroy, quit_cmd);

	if (smtp_client_connection_get_state(client->proxy_conn)
		>= SMTP_CLIENT_CONNECTION_STATE_READY)
		relay_cmd_quit_proxy(quit_cmd);
	return 0;
}

/*
 * Relay backend
 */

static void client_proxy_ready_cb(const struct smtp_reply *reply,
				  void *context)
{
	struct client *client = context;
	enum smtp_capability caps;

	/* check proxy status */
	if ((reply->status / 100) != 2) {
		i_error("Failed to establish relay connection: %s",
			smtp_reply_log(reply));
		client_destroy(client,
			"4.4.0", "Failed to establish relay connection");
		return;
	}

	/* propagate capabilities */
	caps = smtp_client_connection_get_capabilities(client->proxy_conn);
	caps |= SMTP_CAPABILITY_AUTH | SMTP_CAPABILITY_PIPELINING |
		SMTP_CAPABILITY_SIZE | SMTP_CAPABILITY_ENHANCEDSTATUSCODES |
		SMTP_CAPABILITY_CHUNKING | SMTP_CAPABILITY_BURL |
		SMTP_CAPABILITY_VRFY;
	caps &= SUBMISSION_SUPPORTED_SMTP_CAPABILITIES;
	smtp_server_connection_set_capabilities(client->conn, caps);

	/* now that we know our capabilities, commence server protocol dialog */
	smtp_server_connection_resume(client->conn);
}

void client_proxy_start(struct client *client)
{
	smtp_client_connection_connect(client->proxy_conn,
		client_proxy_ready_cb, client);
}
