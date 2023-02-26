/*
 * Copyright (c) 2023 Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Micro Systems Marc Balmer nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Lua binding for Linux */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <alloca.h>
#include <errno.h>
#include <grp.h>
#include <lua.h>
#include <lauxlib.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

#include "lualinux.h"
#include "dirent.h"
#include "pwd.h"
#include "select.h"
#include "dl.h"

extern char *crypt(const char *key, const char *salt);
typedef void (*sighandler_t)(int);

static void
reaper(int signal)
{
	wait(NULL);
}

static int
linux_arc4random(lua_State *L)
{
	lua_pushinteger(L, arc4random());
	return 1;
}

static int
linux_chdir(lua_State *L)
{
	lua_pushinteger(L, chdir(luaL_checkstring(L, 1)));
	return 1;
}

static int
linux_dup2(lua_State *L)
{
	lua_pushinteger(L, dup2(luaL_checkinteger(L, 1),
	    luaL_checkinteger(L, 2)));
	return 1;
}

static int
linux_errno(lua_State *L)
{
	lua_pushinteger(L, errno);
	return 1;
}

static int
linux_strerror(lua_State *L)
{
	lua_pushstring(L, strerror(luaL_checkinteger(L, 1)));
	return 1;
}

static int
linux_fork(lua_State *L)
{
	lua_pushinteger(L, fork());
	return 1;
}

static int
linux_kill(lua_State *L)
{
	lua_pushinteger(L, kill((pid_t)luaL_checkinteger(L, 1),
	    luaL_checkinteger(L, 2)));
	return 1;
}

static int
linux_getcwd(lua_State *L)
{
	char cwd[PATH_MAX];

	if (getcwd(cwd, PATH_MAX) != NULL)
		lua_pushstring(L, cwd);
	else
		lua_pushnil(L);
	return 1;
}

static int
linux_getpass(lua_State *L)
{
	lua_pushstring(L, getpass(luaL_checkstring(L, 1)));
	return 1;
}

static int
linux_getpid(lua_State *L)
{
	lua_pushinteger(L, getpid());
	return 1;
}

static int
linux_setpgid(lua_State *L)
{
	lua_pushinteger(L, setpgid(luaL_checkinteger(L, 1),
	    luaL_checkinteger(L, 2)));
	return 1;
}

static int
linux_sleep(lua_State *L)
{
	lua_pushinteger(L, sleep(luaL_checkinteger(L, 1)));
	return 1;
}

static int
linux_unlink(lua_State *L)
{
	lua_pushinteger(L, unlink(luaL_checkstring(L, 1)));
	return 1;
}

static int
linux_getuid(lua_State *L)
{
	lua_pushinteger(L, getuid());
	return 1;
}

static int
linux_getgid(lua_State *L)
{
	lua_pushinteger(L, getgid());
	return 1;
}

static int
linux_setegid(lua_State *L)
{
	lua_pushboolean(L, setegid(luaL_checkinteger(L, 1)) == 0 ? 1 : 0);
	return 1;
}

static int
linux_seteuid(lua_State *L)
{
	lua_pushboolean(L, seteuid(luaL_checkinteger(L, 1)) == 0 ? 1 : 0);
	return 1;
}

static int
linux_setgid(lua_State *L)
{
	lua_pushboolean(L, setgid(luaL_checkinteger(L, 1)) == 0 ? 1 : 0);
	return 1;
}

static int
linux_setuid(lua_State *L)
{
	lua_pushboolean(L, setuid(luaL_checkinteger(L, 1)) == 0 ? 1 : 0);
	return 1;
}

static int
linux_chown(lua_State *L)
{
	lua_pushinteger(L, chown(luaL_checkstring(L, 1),
	    luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
	return 1;
}

static int
linux_chmod(lua_State *L)
{
	lua_pushinteger(L, chmod(luaL_checkstring(L, 1),
	    luaL_checkinteger(L, 2)));
	return 1;
}

static int
linux_rename(lua_State *L)
{
	lua_pushinteger(L, rename(luaL_checkstring(L, 1),
	    luaL_checkstring(L, 2)));
	return 1;
}

static int
linux_stat(lua_State *L)
{
	struct stat statbuf;

	if (stat(luaL_checkstring(L, 1), &statbuf))
		lua_pushnil(L);
	else {
		lua_newtable(L);
		lua_pushinteger(L, statbuf.st_dev);
		lua_setfield(L, -2, "st_uid");
		lua_pushinteger(L, statbuf.st_ino);
		lua_setfield(L, -2, "st_ino");
		lua_pushinteger(L, statbuf.st_mode);
		lua_setfield(L, -2, "st_mode");
		lua_pushinteger(L, statbuf.st_nlink);
		lua_setfield(L, -2, "st_nlink");
		lua_pushinteger(L, statbuf.st_uid);
		lua_setfield(L, -2, "st_uid");
		lua_pushinteger(L, statbuf.st_gid);
		lua_setfield(L, -2, "st_gid");
		lua_pushinteger(L, statbuf.st_rdev);
		lua_setfield(L, -2, "st_rdev");
		lua_pushinteger(L, statbuf.st_size);
		lua_setfield(L, -2, "st_size");
		lua_pushinteger(L, statbuf.st_blksize);
		lua_setfield(L, -2, "st_blksize");
		lua_pushinteger(L, statbuf.st_blocks);
		lua_setfield(L, -2, "st_blocks");
		lua_pushinteger(L, statbuf.st_atime);
		lua_setfield(L, -2, "st_atime");
		lua_pushinteger(L, statbuf.st_mtime);
		lua_setfield(L, -2, "st_mtime");
		lua_pushinteger(L, statbuf.st_ctime);
		lua_setfield(L, -2, "st_ctime");
	}
	return 1;
}

static int
linux_mkdir(lua_State *L)
{
	lua_pushinteger(L, mkdir(luaL_checkstring(L, 1),
	    luaL_checkinteger(L, 2)));
	return 1;
}

static int
linux_mkstemp(lua_State *L)
{
	int fd;
	char *tmpnam;

	tmpnam = strdup(luaL_checkstring(L, 1));

	fd = mkstemp(tmpnam);
	if (fd == -1) {
		lua_pushnil(L);
		lua_pushnil(L);
	} else {
		lua_pushinteger(L, fd);
		lua_pushstring(L, tmpnam);
	}
	free(tmpnam);
	return 2;
}

static int
linux_ftruncate(lua_State *L)
{
	lua_pushboolean(L,
	    ftruncate(luaL_checkinteger(L, 1), luaL_checkinteger(L, 2))
	    ? 0 : 1);
	return 1;
}

static int
linux_getenv(lua_State *L)
{
	char *v;

	v = getenv(luaL_checkstring(L, 1));
	if (v)
		lua_pushstring(L, v);
	else
		lua_pushnil(L);
	return 1;
}

static int
linux_setenv(lua_State *L)
{
	lua_pushboolean(L, setenv(luaL_checkstring(L, 1),
	    luaL_checkstring(L, 2), lua_toboolean(L, 3)) ? 0 : 1);
	return 1;
}

static int
linux_unsetenv(lua_State *L)
{
	lua_pushboolean(L, unsetenv(luaL_checkstring(L, 1)) ? 0 : 1);
	return 1;
}

static int
linux_crypt(lua_State *L)
{
	lua_pushstring(L, crypt(luaL_checkstring(L, 1),
	    luaL_checkstring(L, 2)));
	return 1;
}

static int
linux_signal(lua_State *L)
{
	sighandler_t old, new;

	new = (sighandler_t)lua_tocfunction(L, 2);
	old = signal(luaL_checkinteger(L, 1), new);

	lua_pushcfunction(L, (lua_CFunction)old);
	return 1;
}

static int
linux_gethostname(lua_State *L)
{
	char name[128];

	if (!gethostname(name, sizeof name))
		lua_pushstring(L, name);
	else
		lua_pushnil(L);
	return 1;
}

static int
linux_sethostname(lua_State *L)
{
	const char *name;
	size_t len;

	name = luaL_checklstring(L, 1, &len);
	if (sethostname(name, len))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
	return 1;
}

static int syslog_options[] = {
	LOG_CONS,
	LOG_NDELAY,
	LOG_NOWAIT,
	LOG_ODELAY,
	LOG_PERROR,
	LOG_PID
};

static const char *syslog_option_names[] = {
	"cons",
	"ndelay",
	"nowait",
	"odelay",
	"perror",
	"pid",
	NULL
};

static int syslog_facilities[] = {
	LOG_AUTH,
	LOG_AUTHPRIV,
	LOG_CRON,
	LOG_DAEMON,
	LOG_FTP,
	LOG_KERN,
	LOG_LOCAL0,
	LOG_LOCAL1,
	LOG_LOCAL2,
	LOG_LOCAL3,
	LOG_LOCAL4,
	LOG_LOCAL5,
	LOG_LOCAL6,
	LOG_LOCAL7,
	LOG_LPR,
	LOG_MAIL,
	LOG_NEWS,
	LOG_SYSLOG,
	LOG_USER,
	LOG_UUCP
};

static const char *syslog_facility_names[] = {
	"auth",
	"authpriv",
	"cron",
	"daemon",
	"ftp",
	"kern",
	"local0",
	"local1",
	"local2",
	"local3",
	"local4",
	"local5",
	"local6",
	"local7",
	"lpr",
	"mail",
	"news",
	"syslog",
	"user",
	"uucp",
	NULL
};

static int
linux_openlog(lua_State *L)
{
	const char *ident;
	int n, option, facility;

	ident = luaL_checkstring(L, 1);

	for (option = 0, n = 2; n < lua_gettop(L); n++)
		option |= syslog_options[luaL_checkoption(L, n, NULL,
		    syslog_option_names)];
	facility = syslog_facilities[luaL_checkoption(L, n, NULL,
	    syslog_facility_names)];
	openlog(ident, option, facility);
	return 0;
}

static int priorities[] = {
	LOG_EMERG,
	LOG_ALERT,
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG
};

static const char *priority_names[] = {
	"emerg",
	"alert",
	"crit",
	"err",
	"warning",
	"notice",
	"info",
	"debug",
	NULL
};

static int
linux_syslog(lua_State *L)
{
	syslog(priorities[luaL_checkoption(L, 1, NULL, priority_names)], "%s",
	    luaL_checkstring(L, 2));
	return 0;
}

static int
linux_closelog(lua_State *L)
{
	closelog();
	return 0;
}

static int
linux_setlogmask(lua_State *L)
{
	lua_pushinteger(L, setlogmask(luaL_checkinteger(L, 1)));
	return 1;
}

static void
linux_set_info(lua_State *L)
{
	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2023 by "
	    "micro systems marc balmer");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "Linux binding for Lua");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");
	lua_pushliteral(L, "linux 1.0.0");
	lua_settable(L, -3);
}

static struct constant linux_constant[] = {
	/* file modes */
	CONSTANT(S_IRUSR),
	CONSTANT(S_IWUSR),
	CONSTANT(S_IXUSR),
	CONSTANT(S_IRGRP),
	CONSTANT(S_IWGRP),
	CONSTANT(S_IXGRP),
	CONSTANT(S_IROTH),
	CONSTANT(S_IWOTH),
	CONSTANT(S_IXOTH),

	/* signals */
	CONSTANT(SIGHUP),
	CONSTANT(SIGINT),
	CONSTANT(SIGQUIT),
	CONSTANT(SIGILL),
	CONSTANT(SIGTRAP),
	CONSTANT(SIGABRT),
	CONSTANT(SIGIOT),
	CONSTANT(SIGBUS),
	CONSTANT(SIGFPE),
	CONSTANT(SIGKILL),
	CONSTANT(SIGUSR1),
	CONSTANT(SIGSEGV),
	CONSTANT(SIGUSR2),
	CONSTANT(SIGPIPE),
	CONSTANT(SIGALRM),
	CONSTANT(SIGTERM),
	CONSTANT(SIGSTKFLT),
	CONSTANT(SIGCHLD),
	CONSTANT(SIGCONT),
	CONSTANT(SIGSTOP),
	CONSTANT(SIGTSTP),
	CONSTANT(SIGTTIN),
	CONSTANT(SIGTTOU),
	CONSTANT(SIGURG),
	CONSTANT(SIGXCPU),
	CONSTANT(SIGXFSZ),
	CONSTANT(SIGVTALRM),
	CONSTANT(SIGPROF),
	CONSTANT(SIGWINCH),
	CONSTANT(SIGPOLL),
	CONSTANT(SIGIO),
	CONSTANT(SIGPWR),
	CONSTANT(SIGSYS),

	{ NULL, 0 }
};

int
luaopen_linux(lua_State *L)
{
	int n;
	struct luaL_Reg lualinux[] = {
		{ "arc4random",	linux_arc4random },
		{ "chdir",	linux_chdir },
		{ "dup2",	linux_dup2 },
		{ "errno",	linux_errno },
		{ "strerror",	linux_strerror },
		{ "fork",	linux_fork },
		{ "kill",	linux_kill },
		{ "getcwd",	linux_getcwd },
		{ "getpass",	linux_getpass },
		{ "getpid",	linux_getpid },
		{ "setpgid",	linux_setpgid },
		{ "sleep",	linux_sleep },
		{ "unlink",	linux_unlink },
		{ "getuid",	linux_getuid },
		{ "getgid",	linux_getgid },
		{ "setegid",	linux_setegid },
		{ "seteuid",	linux_seteuid },
		{ "setgid",	linux_setgid },
		{ "setuid",	linux_setuid },
		{ "chown",	linux_chown },
		{ "chmod",	linux_chmod },
		{ "rename",	linux_rename },
		{ "stat",	linux_stat },
		{ "mkdir" ,	linux_mkdir },
		{ "mkstemp",	linux_mkstemp },
		{ "ftruncate",	linux_ftruncate },

		/* environment */
		{ "getenv",	linux_getenv },
		{ "setenv",	linux_setenv },
		{ "unsetenv",	linux_unsetenv },

		/* crypt */
		{ "crypt",	linux_crypt },

		/* signals */
		{ "signal",	linux_signal },

		{ "setpwent",	linux_setpwent },
		{ "endpwent",	linux_endpwent },
		{ "getpwent",	linux_getpwent },
		{ "getpwnam",	linux_getpwnam },
		{ "getpwuid",	linux_getpwuid },

		/* dirent */
		{ "opendir",	linux_opendir },

		/* dynamic linker */
		{ "dlopen",	linux_dlopen },
		{ "dlerror",	linux_dlerror },
		{ "dlsym",	linux_dlsym },
		{ "dlclose",	linux_dlclose },

		/* shadow password */
		{ "getspnam",	linux_getspnam },

		{ "getgrnam",	linux_getgrnam },
		{ "getgrgid",	linux_getgrgid },

		/* hostname */
		{ "gethostname",	linux_gethostname },
		{ "sethostname",	linux_sethostname },

		/* syslog */
		{ "openlog",	linux_openlog },
		{ "syslog",	linux_syslog },
		{ "closelog",	linux_closelog },
		{ "setlogmask",	linux_setlogmask },

		/* select */
		{ "select",	linux_select },
		{ "fd_set",	linux_fd_set },
		{ NULL, NULL }
	};
	struct luaL_Reg fd_set_methods[] = {
		{ "clr",	linux_fd_set_clr },
		{ "isset",	linux_fd_set_isset },
		{ "set",	linux_fd_set_set },
		{ "zero",	linux_fd_set_zero },
		{ NULL,		NULL }
	};
	struct luaL_Reg dir_methods[] = {
		{ "__gc",	linux_closedir },
		{ "__close",	linux_closedir },
		{ "readdir",	linux_readdir },
		{ "telldir",	linux_telldir },
		{ "seekdir",	linux_seekdir },
		{ "rewinddir",	linux_rewinddir },
		{ "closedir",	linux_closedir },
		{ NULL,		NULL }
	};
	struct luaL_Reg dl_methods[] = {
		{ "__gc",	linux_dlclose },
		{ "__close",	linux_dlclose },
		{ "__index",	linux_dlsym },
		{ NULL,		NULL }
	};
	if (luaL_newmetatable(L, FD_SET_METATABLE)) {
		luaL_setfuncs(L, fd_set_methods, 0);
#if 0
		lua_pushliteral(L, "__gc");
		lua_pushcfunction(L, fd_set_clear);
		lua_settable(L, -3);
#endif
		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

	if (luaL_newmetatable(L, DIR_METATABLE)) {
		luaL_setfuncs(L, dir_methods, 0);

		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);
	if (luaL_newmetatable(L, DL_METATABLE)) {
		luaL_setfuncs(L, dl_methods, 0);

#if 0
		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);
#endif

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);
	if (luaL_newmetatable(L, DLSYM_METATABLE)) {
		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

	luaL_newlib(L, lualinux);
	linux_set_info(L);
	for (n = 0; linux_constant[n].name != NULL; n++) {
		lua_pushinteger(L, linux_constant[n].value);
		lua_setfield(L, -2, linux_constant[n].name);
	};
	lua_pushcfunction(L, (lua_CFunction)SIG_IGN);
	lua_setfield(L, -2, "SIG_IGN");
	lua_pushcfunction(L, (lua_CFunction)SIG_DFL);
	lua_setfield(L, -2, "SIG_DFL");
	lua_pushcfunction(L, (lua_CFunction)reaper);
	lua_setfield(L, -2, "SIG_REAPER");
	return 1;
}
