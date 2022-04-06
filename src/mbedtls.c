#include "mbedtls.h"

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"

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

static LUA_FUNCTION(lmbedtls_base64)
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

static const luaL_Reg lmbedtls_libs[] =
{
    {"hex",       lmbedtls_hex},
    {"base64",    lmbedtls_base64},
    {"hash",      lmbedtls_hash},
    {"hmac",      lmbedtls_hmac},

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

    return 1;
}
