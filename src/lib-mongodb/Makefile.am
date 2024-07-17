module_LTLIBRARIES = libdriver_mongodb.la
libdriver_mongodb_la_LDFLAGS = -module -avoid-version
libdriver_mongodb_la_LIBADD = $(MONGODB_LIBS)
libdriver_mongodb_la_CFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/auth \
	-I$(top_srcdir)/src/lib-auth \
	$(MONGODB_CFLAGS)
libdriver_mongodb_la_SOURCES = driver-mongodb.c
