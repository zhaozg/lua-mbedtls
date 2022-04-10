#ifndef mbedtls_lua_h
#define mbedtls_lua_h

// mbedtls headers
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

#include "mbedtls/platform.h"

// lua headers
#define LUA_LIB

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <errno.h>
#include <string.h>

#include "compat.h"

#define _NAME "mbedtls"
#define _VERSION "0.1.0"

#define LUA_FUNCTION(X) int X(lua_State *L)
#define SIZE_OF_ARRAY(x) (sizeof(x) / sizeof(x[0]))

extern mbedtls_entropy_context lmbedtls_entropy;
extern const char *const proto_lst[];
extern const char *const event_lst[];
extern const char *const switch_lst[];

static inline int mbedtls_newindex(lua_State *L)
{
    void *ud = lua_touserdata(L, 1);
    luaL_checkany(L, 3);

    lua_rawgetp(L, LUA_REGISTRYINDEX, ud);
    if (lua_istable(L, -1))
    {
        lua_pushvalue(L, 2);
        lua_pushvalue(L, 3);
        lua_rawset(L, -3);
    } else
        luaL_argerror(L, 1, "not support assign field value");

    lua_pop(L, 1);

    return 0;
}

static inline int mbedtls_index(lua_State *L)
{
    void *ud = lua_touserdata(L, 1);
    luaL_checkany(L, 2);

    lua_rawgetp(L, LUA_REGISTRYINDEX, ud);
    if (lua_istable(L, -1))
    {
        lua_pushvalue(L, 2);
        lua_rawget(L, -2);

        if (!lua_isnil(L, -1))
            return 1;

        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    lua_getmetatable(L, 1);
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    return 1;
}

static inline int mbedtls_register(lua_State *L, const char *tname,
                                   struct luaL_Reg metamethods[],
                                   struct luaL_Reg methods[]) {
  luaL_newmetatable(L, tname);
  luaL_setfuncs(L, metamethods, 0);

  lua_pushliteral(L, "__name");
  lua_pushstring(L, tname);
  lua_rawset(L, -3);

  lua_pushliteral(L, "__newindex");
  lua_pushcfunction(L, mbedtls_newindex);
  lua_rawset(L, -3);

  lua_pushliteral(L, "__index");
  lua_pushcfunction(L, mbedtls_index);
  lua_rawset(L, -3);

  luaL_setfuncs(L, methods, 0);

  lua_pop(L, 1);
  return 0;
}

static inline int mbedtls_setmetatable(lua_State *L, int idx, const char *tname, void* ud)
{
    idx = lua_absindex(L, idx);
    luaL_getmetatable(L, tname);
    lua_setmetatable(L, idx);

    if (ud)
    {
        lua_newtable(L);
        lua_rawsetp(L, LUA_REGISTRYINDEX, ud);
    }

    return 0;
}

static inline int mbedtls_pusherror(lua_State *L, int err) {
  char msg[256] = {0};

  lua_pushnil(L);
  mbedtls_strerror(err, msg, sizeof(msg));
  lua_pushstring(L, msg);
  lua_pushinteger(L, err);

  return 3;
}

inline static LUA_FUNCTION(mbedtls_tostring) {
  lua_getmetatable(L, 1);
  lua_pushstring(L, "__name");
  lua_rawget(L, -2);

  lua_pushfstring(L, "%s: %p", lua_tostring(L, -1), lua_touserdata(L, 1));
  return 1;
}

LUA_FUNCTION(lmbedtls_hash);
LUA_FUNCTION(lmbedtls_hmac);
LUA_FUNCTION(lmbedtls_rng_new);

// define module names
#define LMBEDTLS_MD_MT "mbedtls.md"
#define LMBEDTLS_PK_MT "mbedtls.pk"
#define LMBEDTLS_NET_MT "mbedtls.net"
#define LMBEDTLS_RNG_MT "mbedtls.rng"
#define LMBEDTLS_TLS_MT "mbedtls.tls"
#define LMBEDTLS_CIPHER_MT "mbedtls.cipher"
#define LMBEDTLS_X509_CRL_MT "mbedtls.x509.crl"
#define LMBEDTLS_X509_CRT_MT "mbedtls.x509.crt"
#define LMBEDTLS_X509_CSR_MT "mbedtls.x509.csr"
#define LMBEDTLS_SSL_SESSION_MT "mbedtls.ssl.session"
#define LMBEDTLS_SSL_CONFIG_MT "mbedtls.ssl.config"
#define LMBEDTLS_SSL_MT "mbedtls.ssl"

// define prototypes
LUALIB_API int luaopen_mbedtls_md(lua_State *L);
LUALIB_API int luaopen_mbedtls_pk(lua_State *L);
LUALIB_API int luaopen_mbedtls_net(lua_State *L);
LUALIB_API int luaopen_mbedtls_rng(lua_State *L);
LUALIB_API int luaopen_mbedtls_ssl(lua_State *L);
LUALIB_API int luaopen_mbedtls_cipher(lua_State *L);
LUALIB_API int luaopen_mbedtls_x509_crl(lua_State *L);
LUALIB_API int luaopen_mbedtls_x509_crt(lua_State *L);
LUALIB_API int luaopen_mbedtls_x509_csr(lua_State *L);
LUALIB_API int luaopen_mbedtls_ssl_config(lua_State *L);
LUALIB_API int luaopen_mbedtls_ssl_session(lua_State *L);
LUALIB_API int luaopen_mbedtls(lua_State *L);

#endif
