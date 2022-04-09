#include "mbedtls.h"

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"

mbedtls_entropy_context lmbedtls_entropy = {0};
const char *const proto_lst[] = {"tcp", "udp", NULL};
const char *const event_lst[] = {"both", "read", "write", NULL};
const char *const switch_lst[] = {"disable", "enable", NULL};

static const char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const char bin[256] =
{
    /*       0, 1, 2, 3, 4, 5, 6, 7, 8, 9, a, b, c, d, e, f */
    /* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 30 */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
    /* 40 */ 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 60 */ 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* a0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* b0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* c0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* d0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* e0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* f0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int
hex2bin(const char *src, unsigned char *dst, int len)
{
    int i;
    if (len == 0)
    {
        len = strlen(src);
    }
    for (i = 0; i < len; i += 2)
    {
        unsigned char h = src[i];
        unsigned char l = src[i + 1];
        dst[i / 2] = bin[h] << 4 | bin[l];
    }
    return i / 2;
}

static int
bin2hex(const unsigned char *src, char *dst, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        unsigned char c = src[i];
        dst[i * 2] = hex[c >> 4];
        dst[i * 2 + 1] = hex[c & 0xf];
    }
    dst[i * 2] = '\0';
    return i * 2;
}

static LUA_FUNCTION(lmbedtls_hex)
{
    size_t l = 0;
    const char *s = luaL_checklstring(L, 1, &l);
    int encode = lua_isnone(L, 2) ? 1 : lua_toboolean(L, 2);
    char *h = NULL;

    if (l == 0)
    {
        lua_pushstring(L, "");
        return 1;
    }

    if (encode)
    {
        h = lua_newuserdata(L, 2 * l + 1);
        l = bin2hex((const unsigned char *)s, h, l);
    }
    else
    {
        h = lua_newuserdata(L, l / 2 + 1);
        l = hex2bin(s, (unsigned char *)h, l);
    }
    lua_pushlstring(L, (const char *)h, l);

    return 1;
}

static LUA_FUNCTION(lmbedtls_version)
{
    char ver[64];

    mbedtls_version_get_string(ver);
    lua_pushstring(L, ver);
    lua_pushinteger(L, mbedtls_version_get_number());

    return 2;
}

static LUA_FUNCTION(lmbedtls_check_feature)
{
    const char *feature = luaL_checkstring(L, 1);

    lua_pushboolean(L, mbedtls_version_check_feature(feature)==0);
    return 1;
}

static
LUA_FUNCTION(lmbedtls_base64)
{
    int ret;
    size_t isz, osz;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &isz);
    int enc = lua_isnone(L, 2) ? 1 : lua_toboolean(L, 2);

    unsigned char *buf = NULL;

    ret = enc ? mbedtls_base64_encode(0, 0, &osz, input, isz)
        : mbedtls_base64_decode(0, 0, &osz, input, isz);
    if (ret==MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        buf = lua_newuserdata(L, osz);
        ret = enc ? mbedtls_base64_encode(buf, osz, &osz, input, isz)
          : mbedtls_base64_decode(buf, osz, &osz, input, isz);
    }
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)buf, osz);
        return 1;
    }
    return mbedtls_pusherror(L, ret);
}

#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"

static LUA_FUNCTION(lmbedtls_debug_set_threshold)
{
    const char *const lst[] = {
        "none", "error", "warning", "info", "verbose", NULL
    };
    int lvl = luaL_checkoption(L, 1, "warning", lst);

    mbedtls_debug_set_threshold(lvl);
    return 0;
}
#endif

static LUA_FUNCTION(lmbedtls_random)
{
    int ret;
    unsigned char output[MBEDTLS_CTR_DRBG_MAX_REQUEST];
    mbedtls_ctr_drbg_context *drbg = NULL;

    int len = luaL_optinteger(L, 1, MBEDTLS_CTR_DRBG_MAX_REQUEST);

    if (len > MBEDTLS_CTR_DRBG_MAX_REQUEST)
    {
        lua_pushfstring(L, "out of range [1, %d]", MBEDTLS_CTR_DRBG_MAX_REQUEST);
        return luaL_argerror(L, 1, lua_tostring(L, -1));
    }

    lua_pushlightuserdata(L, lmbedtls_random);
    lua_rawget(L, LUA_REGISTRYINDEX);
    drbg = luaL_testudata(L, -1, LMBEDTLS_RNG_MT);
    if (drbg == NULL)
        luaL_error(L, "invalid internal state");

    ret = mbedtls_ctr_drbg_random(drbg, output, len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushlstring(L, (const char *)output, len);
    return 1;
}

static const luaL_Reg lmbedtls_libs[] =
{
    {"version",   lmbedtls_version},
    {"hex",       lmbedtls_hex},
    {"base64",    lmbedtls_base64},
    {"hash",      lmbedtls_hash},
    {"hmac",      lmbedtls_hmac},

    {"check_feature",
                  lmbedtls_check_feature},

#if defined(MBEDTLS_DEBUG_C)
    {"debug_set_threshold",
     lmbedtls_debug_set_threshold},
#endif

    {NULL,        NULL}
};

static const luaL_Reg lmbedtls_defined[] =
{
    {"md",        luaopen_mbedtls_md},
    {"pk",        luaopen_mbedtls_pk},
    {"rng",       luaopen_mbedtls_rng},
    {"net",       luaopen_mbedtls_net},
    {"csr",       luaopen_mbedtls_x509_csr},
    {"crl",       luaopen_mbedtls_x509_crl},
    {"crt",       luaopen_mbedtls_x509_crt},
    {"cipher",    luaopen_mbedtls_cipher},
    {"ssl",       luaopen_mbedtls_ssl},

    {NULL,        NULL}
};

static int
lmbedtls_load(lua_State *L)
{
    const luaL_Reg *reg;

    for (reg = lmbedtls_defined; reg->name; reg++)
    {
        lua_pushstring(L, reg->name);
        reg->func(L);
        lua_rawset(L, -3);
    }
    return 0;
}

LUALIB_API
LUA_FUNCTION(luaopen_mbedtls)
{
    mbedtls_entropy_init(    &lmbedtls_entropy);

    luaL_newlib(L, lmbedtls_libs);

    lua_pushliteral(L, _NAME);
    lua_setfield(L, -2, "_NAME");
    lua_pushliteral(L, _VERSION);
    lua_setfield(L, -2, "_VERSION");

    lmbedtls_load(L);

    lua_pushlightuserdata(L, lmbedtls_random);
    lua_pushcfunction(L, lmbedtls_rng_new);
    if (lua_pcall (L, 0, 1, 0)==LUA_OK)
        lua_rawset(L, LUA_REGISTRYINDEX);
    else
        return lua_error(L);

    lua_pushstring(L, "random");
    lua_pushcfunction(L, lmbedtls_random);
    lua_rawset(L, -3);

    return 1;
}
