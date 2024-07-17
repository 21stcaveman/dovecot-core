#include "driver-mongodb.h"

/********** userdb *********************/
#define USER_CACHE_KEY "%u"

struct mongo_userdb_module {
	struct userdb_module module;
	struct userdb_template *tmpl;
};

struct userdb_module_interface userdb_mongo = {
	.name = "mongodb",

	.preinit = mongo_userdb_preinit,
// 	.init = ...,
// 	.deinit = ...,

	.lookup = mongodb_user_lookup,

// 	.iterate_init = ...,
// 	.iterate_next = ...,
// 	.iterate_deinit = ...,
};

static void mongodb_user_lookup(struct auth_request *auth_request ATTR_UNUSED, userdb_callback_t *callback ATTR_UNUSED) {
	i_debug("mongodb driver user lookup");
}

static struct userdb_module *mongo_userdb_preinit(pool_t pool, const char *args) {
	i_debug("mongodb driver user pre-init: args = '%s'", args);

	struct mongo_userdb_module *module;                                                                                                                                                         
	const char *value;
	module = p_new(pool, struct mongo_userdb_module, 1);
	module->module.default_cache_key = USER_CACHE_KEY;
	module->tmpl = userdb_template_build(pool, "mongodb", args);
	module->module.blocking = TRUE;

	if (userdb_template_remove(module->tmpl, "blocking", &value)) {
		module->module.blocking = strcasecmp(value, "yes") == 0;
	}

	return &module->module;
}

/********** passdb *********************/
#define PASSWD_CACHE_KEY "%u"
#define PASSWD_PASS_SCHEME "CRYPT"

struct passdb_module_interface passdb_mongo = {
	.name = "mongodb",

	.preinit = mongo_passdb_preinit,
// 	.init = driver_mongodb_init,
	.deinit = mongo_passdb_deinit,

	.verify_plain = mongo_verify_plain,
// 	.lookup_credentials = ...,
// 	.set_credentials = ...,
};

static void mongo_verify_plain(struct auth_request *request ATTR_UNUSED, const char *password ATTR_UNUSED, verify_plain_callback_t *callback ATTR_UNUSED) {
	i_debug("mongodb driver verify plain pass");
}

static struct passdb_module *mongo_passdb_preinit(pool_t pool, const char *args)
{
	i_debug("mongodb driver pass pre-init: args = '%s'", args);
	struct passdb_module *module;

	module = p_new(pool, struct passdb_module, 1);
	module->blocking = TRUE;
	if (strcmp(args, "blocking=no") == 0) {
		module->blocking = FALSE;
	} else if (*args != '\0') {
		i_fatal("passdb passwd: Unknown setting: %s", args);
	}

	module->default_cache_key = PASSWD_CACHE_KEY;
	module->default_pass_scheme = PASSWD_PASS_SCHEME;
	return module;
}

static void mongo_passdb_deinit(struct passdb_module *module ATTR_UNUSED)
{
	i_debug("mongodb driver pass de-init");
// 	endpwent();
}

/********** driver *********************/

void driver_mongodb_init(struct passdb_module *_module ATTR_UNUSED) {
	i_debug("mongodb driver init");

	passdb_register_module(&passdb_mongo);
	userdb_register_module(&userdb_mongo);
}

void driver_mongodb_deinit(struct passdb_module *_module ATTR_UNUSED) {
	i_debug("mongodb driver de-init");

	passdb_unregister_module(&passdb_mongo);
	userdb_unregister_module(&userdb_mongo);
}
