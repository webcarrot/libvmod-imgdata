INCLUDES = -I$(VARNISHSRC)/include -I$(VARNISHSRC)

vmoddir = $(VMODDIR)
vmod_LTLIBRARIES = libvmod_imgdata.la

libvmod_imgdata_la_CFLAGS = `curl-config --cflags 2>/dev/null`
libvmod_imgdata_la_LDFLAGS = -module -export-dynamic -avoid-version `curl-config --libs 2>/dev/null`

libvmod_imgdata_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_imgdata.c

vcc_if.c vcc_if.h: $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_imgdata.vcc
	@PYTHON@ $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_imgdata.vcc

EXTRA_DIST = \
	vmod_imgdata.vcc

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h
