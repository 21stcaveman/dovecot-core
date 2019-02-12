/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * EHLO, HELO commands
 */

void submission_helo_reply_submit(struct smtp_server_cmd_ctx *cmd,
				  struct smtp_server_cmd_helo *data)
{
	struct client *client = smtp_server_connection_get_context(cmd->conn);
	enum smtp_capability proxy_caps =
		smtp_client_connection_get_capabilities(client->proxy_conn);
	struct smtp_server_reply *reply;
	uoff_t cap_size;

	reply = smtp_server_reply_create_ehlo(cmd->cmd);
	if (!data->helo.old_smtp) {
		string_t *burl_params = t_str_new(256);

		str_append(burl_params, "imap");
		if (*client->set->imap_urlauth_host == '\0' ||
			strcmp(client->set->imap_urlauth_host,
			       URL_HOST_ALLOW_ANY) == 0) {
			str_printfa(burl_params, " imap://%s",
				    client->set->hostname);
		} else {
			str_printfa(burl_params, " imap://%s",
				    client->set->imap_urlauth_host);
		}
		if (client->set->imap_urlauth_port != 143) {
			str_printfa(burl_params, ":%u",
				    client->set->imap_urlauth_port);
		}

		if ((proxy_caps & SMTP_CAPABILITY_8BITMIME) != 0)
			smtp_server_reply_ehlo_add(reply, "8BITMIME");
		smtp_server_reply_ehlo_add(reply, "AUTH");
		if ((proxy_caps & SMTP_CAPABILITY_BINARYMIME) != 0 &&
			(proxy_caps & SMTP_CAPABILITY_CHUNKING) != 0)
			smtp_server_reply_ehlo_add(reply, "BINARYMIME");
		smtp_server_reply_ehlo_add_param(reply,
			"BURL", "%s", str_c(burl_params));
		smtp_server_reply_ehlo_add(reply, "CHUNKING");
		if ((proxy_caps & SMTP_CAPABILITY_DSN) != 0)
			smtp_server_reply_ehlo_add(reply, "DSN");
		smtp_server_reply_ehlo_add(reply,
			"ENHANCEDSTATUSCODES");
		smtp_server_reply_ehlo_add(reply,
			"PIPELINING");

		cap_size = client_get_max_mail_size(client);
		if (cap_size > 0) {
			smtp_server_reply_ehlo_add_param(reply,
				"SIZE", "%"PRIuUOFF_T, cap_size);
		} else {
			smtp_server_reply_ehlo_add(reply, "SIZE");
		}
		smtp_server_reply_ehlo_add(reply, "VRFY");
	}
	smtp_server_reply_submit(reply);
}

