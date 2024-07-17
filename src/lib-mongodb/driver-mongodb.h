#include "auth-common.h"
#include "config.h"
#include <bson/bson.h>
#include <mongoc/mongoc.h>

const char *mongodb_plugin_version = DOVECOT_ABI_VERSION;

void driver_mongodb_init(struct passdb_module *);
void driver_mongodb_deinit(struct passdb_module *);

/********** userdb *********************/
#include "userdb.h"
#include "userdb-template.h"

static struct userdb_module *mongo_userdb_preinit(pool_t, const char *);
static void mongodb_user_lookup(struct auth_request *, userdb_callback_t *);

/********** passdb *********************/
#include "passdb.h"

static void mongo_verify_plain(struct auth_request *, const char *, verify_plain_callback_t *);
static struct passdb_module *mongo_passdb_preinit(pool_t, const char *);
static void mongo_passdb_deinit(struct passdb_module * ATTR_UNUSED);
