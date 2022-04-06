#include "mbedtls.h"

static LUA_FUNCTION(lmbedtls_crl_parse_file)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#if defined(MBEDTLS_FS_IO)
    mbedtls_x509_crl *crl = luaL_checkudata(L, 1, LMBEDTLS_X509_CRL_MT);
    const char *path = luaL_checkstring(L, 2);
    ret = mbedtls_x509_crl_parse_file(crl, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_crl_parse)
{
    int ret;
    mbedtls_x509_crl *crl = luaL_checkudata(L, 1, LMBEDTLS_X509_CRL_MT);
    size_t blen;
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &blen);
    int der = lua_toboolean(L, 3);

    if (der)
    {
        ret = mbedtls_x509_crl_parse_der(crl, buf, blen);
    }
    else
    {
        ret = mbedtls_x509_crl_parse(crl, buf, blen);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_crl_info)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    mbedtls_x509_crl *crl = luaL_checkudata(L, 1, LMBEDTLS_X509_CRL_MT);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    const char* title = luaL_optstring(L, 2, "");
    char buf[4096];

    ret = mbedtls_x509_crl_info(buf, sizeof( buf ) - 1, title, crl);
    if (ret>0)
    {
        lua_pushlstring(L, buf, ret);
        return 1;
    }
#endif
    return mbedtls_pusherror(L, ret);
    return 0;
}

static LUA_FUNCTION(lmbedtls_crl_gc)
{
    mbedtls_x509_crl *crl = luaL_checkudata(L, 1, LMBEDTLS_X509_CRL_MT);
    mbedtls_x509_crl_free(crl);
    return 0;
}


static LUA_FUNCTION(lmbedtls_crl_new)
{
    mbedtls_x509_crl *crl = lua_newuserdata(L, sizeof(mbedtls_x509_crl));

    if (!crl)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_x509_crl_init(crl);

    luaL_getmetatable(L, LMBEDTLS_X509_CRL_MT);
    lua_setmetatable(L, -2);

    return 1;
}

struct luaL_Reg crl_meta[] =
{
    {"__gc",       lmbedtls_crl_gc},
    {"__tostring", mbedtls_tostring},

    {NULL, NULL}
};

struct luaL_Reg crl_methods[] =
{
    {"parse",      lmbedtls_crl_parse},
    {"parse_file", lmbedtls_crl_parse_file},
    {"info",       lmbedtls_crl_info},

    {NULL, NULL}
};

struct luaL_Reg crl_libs[] =
{
    {"new",        lmbedtls_crl_new},

    {NULL, NULL}
};

LUALIB_API int
luaopen_mbedtls_x509_crl(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_X509_CRL_MT, crl_meta, crl_methods);

    luaL_newlib(L, crl_libs);
    return 1;
}
