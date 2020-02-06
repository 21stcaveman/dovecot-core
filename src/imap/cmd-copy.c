/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-resp-code.h"
#include "imap-util.h"
#include "imap-commands.h"
#include "imap-search-args.h"

#include <time.h>

#define COPY_CHECK_INTERVAL 100

struct cmd_copy_context {
	struct client_command_context *cmd;
	struct mailbox *destbox;
	bool move;

	struct mailbox_transaction_context *src_trans;
	struct msgset_generator_context srcset_ctx;
	unsigned int copy_count;
};

static void client_send_sendalive_if_needed(struct client *client)
{
	time_t now, last_io;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	now = time(NULL);
	last_io = I_MAX(client->last_input, client->last_output);
	if (now - last_io > MAIL_STORAGE_STAYALIVE_SECS) {
		o_stream_nsend_str(client->output, "* OK Hang in there..\r\n");
		/* make sure it doesn't get stuck on the corked stream */
		o_stream_uncork(client->output);
		o_stream_cork(client->output);
		client->last_output = now;
	}
}

static void copy_update_trashed(struct client *client, struct mailbox *box,
				unsigned int count)
{
	const struct mailbox_settings *set;

	set = mailbox_settings_find(mailbox_get_namespace(box),
				    mailbox_get_vname(box));
	if (set != NULL && set->special_use[0] != '\0' &&
	    str_array_icase_find(t_strsplit_spaces(set->special_use, " "),
				 "\\Trash"))
		client->trashed_count += count;
}

static int fetch_and_copy(struct cmd_copy_context *copy_ctx,
			  struct mail_search_args *search_args,
			  struct mail_transaction_commit_changes *changes_r)
{
	struct client *client = copy_ctx->cmd->client;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	const char *cmd_reason;
	int ret;

	i_assert(o_stream_is_corked(client->output) ||
		 client->output->stream_errno != 0);

	cmd_reason = imap_client_command_get_reason(copy_ctx->cmd);
	t = mailbox_transaction_begin(copy_ctx->destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL |
				      MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS,
				      cmd_reason);

	copy_ctx->src_trans =
		mailbox_transaction_begin(client->mailbox, 0, cmd_reason);
	search_ctx = mailbox_search_init(copy_ctx->src_trans, search_args,
					 NULL, 0, NULL);

	ret = 1;
	while (mailbox_search_next(search_ctx, &mail) && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		if ((++copy_ctx->copy_count % COPY_CHECK_INTERVAL) == 0)
			client_send_sendalive_if_needed(client);

		save_ctx = mailbox_save_alloc(t);
		mailbox_save_copy_flags(save_ctx, mail);

		if (copy_ctx->move) {
			if (mailbox_move(&save_ctx, mail) < 0)
				ret = -1;
		} else {
			if (mailbox_copy(&save_ctx, mail) < 0)
				ret = -1;
		}
		if (ret < 0 && mail->expunged)
			ret = 0;

		msgset_generator_next(&copy_ctx->srcset_ctx, mail->uid);
	}

	if (ret <= 0)
		mailbox_transaction_rollback(&t);
	else if (mailbox_transaction_commit_get_changes(&t, changes_r) < 0) {
		if (mailbox_get_last_mail_error(copy_ctx->destbox) == MAIL_ERROR_EXPUNGED) {
			/* storage backend didn't notice the expunge until
			   at commit time. */
			ret = 0;
		} else {
			ret = -1;
		}
	}

	msgset_generator_finish(&copy_ctx->srcset_ctx);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	return ret;
}

static bool cmd_copy_full(struct client_command_context *cmd, bool move)
{
	struct client *client = cmd->client;
	struct mail_storage *dest_storage;
	struct mailbox *destbox;
        struct mail_search_args *search_args;
	const char *messageset, *mailbox;
	enum mailbox_sync_flags sync_flags = 0;
	enum imap_sync_flags imap_flags = 0;
	struct mail_transaction_commit_changes changes;
	struct cmd_copy_context copy_ctx;
	string_t *msg, *src_uidset;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	ret = imap_search_get_seqset(cmd, messageset, cmd->uid, &search_args);
	if (ret <= 0)
		return ret < 0;

	if (client_open_save_dest_box(cmd, mailbox, &destbox) < 0) {
		mail_search_args_unref(&search_args);
		return TRUE;
	}

	i_zero(&copy_ctx);
	copy_ctx.cmd = cmd;
	copy_ctx.destbox = destbox;
	copy_ctx.move = move;
	src_uidset = t_str_new(256);
	msgset_generator_init(&copy_ctx.srcset_ctx, src_uidset);
	ret = fetch_and_copy(&copy_ctx, search_args, &changes);
	mail_search_args_unref(&search_args);

	msg = t_str_new(256);
	if (ret <= 0)
		;
	else if (copy_ctx.copy_count == 0) {
		str_append(msg, "OK No messages found.");
		pool_unref(&changes.pool);
	} else if (seq_range_count(&changes.saved_uids) == 0 ||
		   changes.no_read_perm) {
		/* not supported by backend (virtual) or no read permissions
		   for mailbox */
		str_append(msg, move ? "OK Move completed." :
			   "OK Copy completed.");
		pool_unref(&changes.pool);
	} else if (move) {
		i_assert(copy_ctx.copy_count == seq_range_count(&changes.saved_uids));
		copy_update_trashed(client, destbox, copy_ctx.copy_count);

		str_printfa(msg, "* OK [COPYUID %u %s ",
			    changes.uid_validity, str_c(src_uidset));
		imap_write_seq_range(msg, &changes.saved_uids);
		str_append(msg, "] Moved UIDs.");
		client_send_line(client, str_c(msg));

		str_truncate(msg, 0);
		str_append(msg, "OK Move completed.");
		pool_unref(&changes.pool);
	} else {
		i_assert(copy_ctx.copy_count == seq_range_count(&changes.saved_uids));
		copy_update_trashed(client, destbox, copy_ctx.copy_count);

		str_printfa(msg, "OK [COPYUID %u %s ", changes.uid_validity,
			    str_c(src_uidset));
		imap_write_seq_range(msg, &changes.saved_uids);
		str_append(msg, "] Copy completed.");
		pool_unref(&changes.pool);
	}

	if (ret <= 0 && move) {
		/* move failed, don't expunge anything */
		mailbox_transaction_rollback(&copy_ctx.src_trans);
	} else {
		if (mailbox_transaction_commit(&copy_ctx.src_trans) < 0)
			ret = -1;
	}

 	dest_storage = mailbox_get_storage(destbox);
	if (destbox != client->mailbox) {
		if (move)
			sync_flags |= MAILBOX_SYNC_FLAG_EXPUNGE;
		else
			sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		imap_flags |= IMAP_SYNC_FLAG_SAFE;
		mailbox_free(&destbox);
	} else if (move) {
		sync_flags |= MAILBOX_SYNC_FLAG_EXPUNGE;
		imap_flags |= IMAP_SYNC_FLAG_SAFE;
	}

	if (ret > 0)
		return cmd_sync(cmd, sync_flags, imap_flags, str_c(msg));
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(cmd, 0, 0,
			"NO ["IMAP_RESP_CODE_EXPUNGEISSUED"] "
			"Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(cmd, dest_storage);
		return TRUE;
	}
}

bool cmd_copy(struct client_command_context *cmd)
{
	return cmd_copy_full(cmd, FALSE);
}

bool cmd_move(struct client_command_context *cmd)
{
	return cmd_copy_full(cmd, TRUE);
}
