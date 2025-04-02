#include "mbedtls.h"

static LUA_FUNCTION(lmbedtls_crt_parse_file)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#if defined(MBEDTLS_FS_IO)
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    const char *path = luaL_checkstring(L, 2);
    ret = mbedtls_x509_crt_parse_file(crt, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_crt_parse_path)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#if defined(MBEDTLS_FS_IO)
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    const char *path = luaL_checkstring(L, 2);
    ret = mbedtls_x509_crt_parse_path(crt, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_crt_parse)
{
    int ret;
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    size_t blen;
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &blen);
    int der = lua_toboolean(L, 3);

    if (der)
    {
        ret = mbedtls_x509_crt_parse_der(crt, buf, blen);
    }
    else
    {
        ret = mbedtls_x509_crt_parse(crt, buf, blen);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_crt_info)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    const char* title = luaL_optstring(L, 2, "");
    char buf[4096];

    ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, title, crt);
    if (ret>0)
    {
        lua_pushlstring(L, buf, ret);
        return 1;
    }
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_crt_verify_info)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    uint32_t flags = (uint32_t)luaL_checkinteger(L, 1);
    const char* title = luaL_optstring(L, 2, "");
    char buf[4096];

    ret = mbedtls_x509_crt_verify_info(buf, sizeof( buf ) - 1, title, flags);
    if (ret>0)
    {
        lua_pushlstring(L, buf, ret);
        return 1;
    }
#endif
    return mbedtls_pusherror(L, ret);
}

static int lmbedtls_crt_vrfy(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    lua_State *L = data;
    int ret = 0;

    lua_rawgetp(L, LUA_REGISTRYINDEX, lmbedtls_crt_vrfy);
    lua_pushlstring(L, (const char*)crt->raw.p, crt->raw.len);
    lua_pushinteger(L, depth);

    ret = lua_pcall(L, 2, 1, 0);
    if (ret != LUA_OK)
    {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    else
    {
        *flags = (uint32_t)lua_tonumber(L, -1);
    }
    lua_pop(L, 1);

    return ret;
}

static LUA_FUNCTION(lmbedtls_crt_verify)
{
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    mbedtls_x509_crt *ca = luaL_checkudata(L, 3, LMBEDTLS_X509_CRT_MT);
    mbedtls_x509_crl *crl = luaL_checkudata(L, 3, LMBEDTLS_X509_CRL_MT);
    const char *cn = luaL_optstring(L, 4, NULL);
    uint32_t flags = 0;
    int ret;

    luaL_argcheck(L, lua_isnone(L, 5) || lua_isfunction(L, 5), 5,
                  "only accept none or function");

    if (lua_isfunction(L, 5))
    {
        lua_pushvalue(L, 5);
        lua_rawsetp(L, LUA_REGISTRYINDEX, lmbedtls_crt_vrfy);
        ret = mbedtls_x509_crt_verify(crt, ca, crl, cn, &flags, lmbedtls_crt_vrfy, L);
    }
    else
        ret = mbedtls_x509_crt_verify(crt, ca, crl, cn, &flags, NULL, NULL);

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_crt_check_key_usage)
{
    int ret;
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    luaL_argcheck(L, lua_isstring(L, 1) || lua_isnumber(L,1), 1,
                  "only accept number or string");

    if (lua_isnumber(L, 1))
    {
        unsigned int usage = lua_tointeger(L, 1);
        ret = mbedtls_x509_crt_check_key_usage(crt, usage);
    }
    else
    {
        size_t ulen;
        const char *usage_oid = luaL_checklstring(L, 2, &ulen);
        ret = mbedtls_x509_crt_check_extended_key_usage(crt, usage_oid, ulen);
    }

    if (ret==0)
    {
        lua_pushboolean(L, 1);
        ret = 1;
    }
    else if (ret==MBEDTLS_ERR_X509_BAD_INPUT_DATA)
    {
        lua_pushboolean(L, 0);
        ret = 1;
    }
    else
    {
        return mbedtls_pusherror(L, ret);
    }

    return ret;
}

static LUA_FUNCTION(lmbedtls_crt_is_revoked)
{
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    mbedtls_x509_crl *crl = luaL_checkudata(L, 2, LMBEDTLS_X509_CRL_MT);

    int ret = mbedtls_x509_crt_is_revoked(crt, crl);
    if (ret==1 || ret==0)
    {
        lua_pushboolean(L, ret);
        return 1;
    }

    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_crt_gc)
{
    mbedtls_x509_crt *crt = luaL_checkudata(L, 1, LMBEDTLS_X509_CRT_MT);
    mbedtls_x509_crt_free(crt);
    return 0;
}


static LUA_FUNCTION(lmbedtls_crt_new)
{
    mbedtls_x509_crt *crt = lua_newuserdata(L, sizeof(mbedtls_x509_crt));

    if (!crt)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_x509_crt_init(crt);

    mbedtls_setmetatable(L, -1, LMBEDTLS_X509_CRT_MT, NULL);
    return 1;
}

struct luaL_Reg crt_meta[] =
{
    {"__gc",         lmbedtls_crt_gc},
    {"__tostring",   mbedtls_tostring},

    {NULL, NULL}
};

struct luaL_Reg crt_methods[] =
{
    {"parse",        lmbedtls_crt_parse},
    {"parse_file",   lmbedtls_crt_parse_file},
    {"parse_path",   lmbedtls_crt_parse_path},
    {"info",         lmbedtls_crt_info},
    {"verify",       lmbedtls_crt_verify},
    {"check_usage",  lmbedtls_crt_check_key_usage},
    {"is_revoked",   lmbedtls_crt_is_revoked},

    {NULL, NULL}
};

struct luaL_Reg crt_libs[] =
{
    {"new",          lmbedtls_crt_new},
    {"verify_info",  lmbedtls_crt_verify_info},

    {NULL, NULL}
};

LUALIB_API int
luaopen_mbedtls_x509_crt(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_X509_CRT_MT, crt_meta, crt_methods);

    luaL_newlib(L, crt_libs);
    return 1;
}
