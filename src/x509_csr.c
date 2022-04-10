#include "mbedtls.h"

static LUA_FUNCTION(lmbedtls_csr_parse_file)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#if defined(MBEDTLS_FS_IO)
    mbedtls_x509_csr *csr = luaL_checkudata(L, 1, LMBEDTLS_X509_CSR_MT);
    const char *path = luaL_checkstring(L, 2);
    ret = mbedtls_x509_csr_parse_file(csr, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_csr_parse)
{
    int ret;
    mbedtls_x509_csr *csr = luaL_checkudata(L, 1, LMBEDTLS_X509_CSR_MT);
    size_t blen;
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &blen);
    int der = lua_toboolean(L, 3);

    if (der)
    {
        ret = mbedtls_x509_csr_parse_der(csr, buf, blen);
    }
    else
    {
        ret = mbedtls_x509_csr_parse(csr, buf, blen);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_csr_info)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    mbedtls_x509_csr *csr = luaL_checkudata(L, 1, LMBEDTLS_X509_CSR_MT);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    const char* title = luaL_optstring(L, 2, "");
    char buf[4096];

    ret = mbedtls_x509_csr_info(buf, sizeof( buf ) - 1, title, csr);
    if (ret>0)
    {
        lua_pushlstring(L, buf, ret);
        return 1;
    }
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_csr_gc)
{
    mbedtls_x509_csr *csr = luaL_checkudata(L, 1, LMBEDTLS_X509_CSR_MT);
    mbedtls_x509_csr_free(csr);
    return 0;
}


static LUA_FUNCTION(lmbedtls_csr_new)
{
    mbedtls_x509_csr *csr = lua_newuserdata(L, sizeof(mbedtls_x509_csr));

    if (!csr)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_x509_csr_init(csr);

    mbedtls_setmetatable(L, -1, LMBEDTLS_X509_CSR_MT, NULL);

    return 1;
}

struct luaL_Reg csr_meta[] =
{
    {"__gc",         lmbedtls_csr_gc},
    {"__tostring",   mbedtls_tostring},

    {NULL, NULL}
};

struct luaL_Reg csr_methods[] =
{
    {"parse",        lmbedtls_csr_parse},
    {"parse_file",   lmbedtls_csr_parse_file},
    {"info",         lmbedtls_csr_info},

    {NULL, NULL}
};

struct luaL_Reg csr_libs[] =
{
    {"new",          lmbedtls_csr_new},

    {NULL, NULL}
};

LUALIB_API int
luaopen_mbedtls_x509_csr(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_X509_CSR_MT, csr_meta, csr_methods);

    luaL_newlib(L, csr_libs);
    return 1;
}
