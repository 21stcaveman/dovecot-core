#ifndef LMTP_RECIPIENT_H
#define LMTP_RECIPIENT_H

struct smtp_address;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct smtp_server_recipient;
struct client;

enum lmtp_recipient_type {
	LMTP_RECIPIENT_TYPE_LOCAL,
	LMTP_RECIPIENT_TYPE_PROXY,
};

struct lmtp_recipient {
	struct client *client;
	struct smtp_server_recipient *rcpt;

	enum lmtp_recipient_type type;
	void *backend_context;
};

struct lmtp_recipient *
lmtp_recipient_create(struct client *client,
		      struct smtp_server_recipient *rcpt);

struct lmtp_recipient *
lmtp_recipient_find_duplicate(struct lmtp_recipient *lrcpt,
			      struct smtp_server_transaction *trans);

#endif
