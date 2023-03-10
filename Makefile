SRCS=		lualinux.c
MODULE=		linux

MKDIR?=		../../mk/

LDADD+=		-lbsd -lcrypt

SUBDIR+=	dirent dl pwd sys

include $(MKDIR)lua.module.mk
