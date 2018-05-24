## Process this file with automake to produce Makefile.in

extlib_LTLIBRARIES = acl_wl.la

acl_wl_la_SOURCES = \
        acl_wl.c \
        aw_tree.c \
        lex.aw_conf.c \
        aw_conf.tab.c

AM_LDFLAGS = \
        -module -avoid-version -shared

AM_CPPFLAGS = \
        -I$(top_srcdir)/include

AM_CFLAGS = \
        -Wall
%.tab.c %.tab.h: %.y
	bison -d $<
lex.aw_conf.c: aw_conf.l
	lex -o $@ aw_conf.l

MAINTAINERCLEANFILES = Makefile.in
MOSTLYCLEANFILES = *.stackdump
