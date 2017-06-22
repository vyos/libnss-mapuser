
NAME_SOURCE=nss_mapname.c map_common.c
NSSNAMELIB =libnss_mapname.so.2
UID_SOURCE=nss_mapuid.c map_common.c
NSSUIDLIB =libnss_mapuid.so.2

# set to x86_64-linux-gnu, arm-linux-gnueabi, etc. by packaging tools
# If not set, just install directly to /lib
LIBDIR=/lib/${DEB_TARGET_GNU_TYPE}

CC = gcc

ifneq (,$(filter noopt,$(DEB_BUILD_OPTIONS)))
		OPTFLAGS = -O2
else
		OPTFLAGS = -g3 -O0
endif
ifeq (,$(filter nostrip,$(DEB_BUILD_OPTIONS)))
	STRIP = strip
    FVISIBILITY = -fvisibility=hidden
else
	STRIP=echo Nostrip
    FVISIBILITY = -fvisibility=default
endif

CPPFLAGS = -D_FORTIFY_SOURCE=2
CFLAGS = $(CPPFLAGS) ${OPTFLAGS} -fPIC -fstack-protector-strong \
		 -Wformat -Werror=format-security -Wall $(FVISIBILITY)
LDFLAGS = -shared  -fPIC -DPIC \
		  -Wl,-z -Wl,relro -Wl,-z -Wl,now -Wl,-soname -Wl,$@

all: $(NSSNAMELIB) $(NSSUIDLIB)

$(NSSUIDLIB): $(UID_SOURCE:.c=.o)
	$(CC) $(LDFLAGS) $^ -o $@

$(NSSNAMELIB): $(NAME_SOURCE:.c=.o)
	$(CC) $(LDFLAGS) $^ -o $@

install: all
	install -m 755 -d $(DESTDIR)/$(LIBDIR) $(DESTDIR)/etc
	install -m 644 $(NSSNAMELIB) $(NSSUIDLIB) $(DESTDIR)$(LIBDIR)
	$(STRIP) --strip-all --keep-symbol=_nss_mapname_getpwnam_r \
			$(DESTDIR)$(LIBDIR)/${NSSNAMELIB}
	$(STRIP) --strip-all --keep-symbol=_nss_mapuid_getpwuid_r \
			$(DESTDIR)$(LIBDIR)/${NSSUIDLIB}
	install -m 644 nss_mapuser.conf $(DESTDIR)/etc/

clean:
	rm -f *.o $(NSSNAMELIB) $(NSSUIDLIB)

.PHONY: all install clean distclean
