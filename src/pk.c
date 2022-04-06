#include "mbedtls.h"

#include "mbedtls/pk.h"


static LUA_FUNCTION(lmbedtls_pk_write)
{
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    int pub = lua_toboolean(L, 2);
    int der = lua_toboolean(L, 3);
    size_t blen = 0;
    unsigned char *buf = NULL;
    int (*write_fn)(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size) = NULL;

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PEM_WRITE_C)
    if (der)
    {
        write_fn = pub ? mbedtls_pk_write_pubkey_der
               : mbedtls_pk_write_key_der;
    }

    else
    {
        write_fn = pub ? mbedtls_pk_write_pubkey_pem
               : mbedtls_pk_write_key_pem;
    }
#elif defined(MBEDTLS_PK_WRITE_C)
    write_fn = pub ? mbedtls_pk_write_pubkey_der
             : mbedtls_pk_write_key_der;
#endif

    if (write_fn)
    {
        ret = write_fn(pk, buf, blen);
        if (ret > 0)
        {
            buf = mbedtls_calloc(1, blen);
            ret = write_fn(pk, buf, blen);
            if (ret > 0)
            {
                lua_pushlstring(L, (const char *)buf, blen);
                mbedtls_free(buf);
                return 1;
            }
            mbedtls_free(buf);
        }
        return mbedtls_pusherror(L, ret);
    }

    return mbedtls_pusherror(L, MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);
}

static LUA_FUNCTION(lmbedtls_pk_encrypt)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    size_t ilen = 0;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 3, LMBEDTLS_RNG_MT);
    size_t olen = ilen + 3*MBEDTLS_MD_MAX_SIZE + 4*4;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_pk_encrypt(pk, input, ilen, output, &olen, olen,
                                 mbedtls_ctr_drbg_random, drbg);
    if (ret)
    {
        ret = mbedtls_pusherror(L, ret);
    }
    else
    {
        lua_pushlstring(L, (const char *)output, olen);
        ret = 1;
    }
    mbedtls_free(output);
    return ret;
}

static LUA_FUNCTION(lmbedtls_pk_decrypt)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    size_t ilen = 0;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 3, LMBEDTLS_RNG_MT);
    size_t olen = ilen + 3*MBEDTLS_MD_MAX_SIZE + 4*4;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_pk_decrypt(pk, input, ilen, output, &olen, olen,
                                 mbedtls_ctr_drbg_random, drbg);
    if (ret)
    {
        ret = mbedtls_pusherror(L, ret);
    }
    else
    {
        lua_pushlstring(L, (const char *)output, olen);
        ret = 1;
    }
    mbedtls_free(output);
    return ret;
}

static LUA_FUNCTION(lmbedtls_pk_sign)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    size_t hlen = 0;
    const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 2, &hlen);
    mbedtls_md_type_t alg = luaL_checkinteger(L, 3);
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 4, LMBEDTLS_RNG_MT);
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE] = {0};
    size_t slen = sizeof(sig);

    int ret = mbedtls_pk_sign(pk, alg, hash, hlen, sig, slen, &slen,
                              mbedtls_ctr_drbg_random, drbg);
    if (ret)
    {
        ret = mbedtls_pusherror(L, ret);
    }
    else
    {
        lua_pushlstring(L, (const char *)sig, slen);
        ret = 1;
    }
    return ret;
}

static LUA_FUNCTION(lmbedtls_pk_verify)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    size_t hlen = 0;
    const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 2, &hlen);
    mbedtls_md_type_t alg = luaL_checkinteger(L, 3);
    size_t slen;
    const unsigned char *sig = (const unsigned char *)luaL_checklstring(L, 4, &slen);

    int ret = mbedtls_pk_verify(pk, alg, hash, hlen, sig, slen);
    if (ret)
    {
        ret = mbedtls_pusherror(L, ret);
    }
    else
    {
        lua_pushboolean(L, 1);
        ret = 1;
    }
    return ret;
}

static LUA_FUNCTION(lmbedtls_pk_cando)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    mbedtls_pk_type_t type = luaL_checkinteger(L, 2);

    lua_pushboolean(L, mbedtls_pk_can_do(pk, type) != 0);
    return 1;
}

static LUA_FUNCTION(lmbedtls_pk_get)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    const char *key = luaL_checkstring(L, 2);

    if (strcasecmp(key, "type"))
    {
        mbedtls_pk_type_t type = mbedtls_pk_get_type(pk);
        lua_pushinteger(L, type);
        return 1;
    }
    else if (strcasecmp(key, "name"))
    {
        const char *name = mbedtls_pk_get_name(pk);
        lua_pushstring(L, name);
        return 1;
    }
    else if (strcasecmp(key, "len"))
    {
        lua_pushinteger(L, mbedtls_pk_get_len(pk));
        return 1;
    }
    else if (strcasecmp(key, "bitlen"))
    {
        lua_pushinteger(L, mbedtls_pk_get_bitlen(pk));
        return 1;
    }

    luaL_argerror(L, 2, strerror(EINVAL));
    return 0;
}

static LUA_FUNCTION(lmbedtls_pk_checkpair)
{
    const mbedtls_pk_context *pub = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    const mbedtls_pk_context *prv = luaL_checkudata(L, 2, LMBEDTLS_PK_MT);
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 3, LMBEDTLS_RNG_MT);
    int ret = mbedtls_pk_check_pair(pub, prv, mbedtls_ctr_drbg_random, drbg);

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushboolean(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_pk_tostring)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    lua_pushfstring(L, "%s: %p", LMBEDTLS_PK_MT, pk);

    return 1;
}

static LUA_FUNCTION(lmbedtls_pk_gc)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);

    mbedtls_pk_free(pk);
    return 0;
}


static LUA_FUNCTION(lmbedtls_pk_genkey)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 2, LMBEDTLS_RNG_MT);
    mbedtls_pk_type_t type = mbedtls_pk_get_type(pk);
    int ret = 0;

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (type == MBEDTLS_PK_RSA)
    {
        unsigned int nbits = luaL_optinteger(L, 3, 4096);
        int exponent = luaL_optinteger(L, 4, 65537);

        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random,
                                  drbg, nbits, exponent);
    }
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECDSA
        || type == MBEDTLS_PK_ECKEY_DH)
    {
        mbedtls_ecp_group_id gid = luaL_checkinteger(L, 3);

        ret = mbedtls_ecp_gen_key(gid, mbedtls_pk_ec(*pk),
                                  mbedtls_ctr_drbg_random, drbg);
    }
    else
#endif
    {
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_pk_parsefile)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    const char *path = luaL_checkstring(L, 2);
    const char *pwd = NULL;
    int pub = 0;

    if (lua_isstring(L, 3))
    {
        pwd = lua_tostring(L, 3);
    }
    else if(lua_isboolean(L, 3))
    {
        pub = lua_toboolean(L, 3);
    }

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_FS_IO)
    if (pub)
    {
        ret = mbedtls_pk_parse_public_keyfile(pk, path);
    }
    else
    {
        mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 4, LMBEDTLS_RNG_MT);
        ret = mbedtls_pk_parse_keyfile(pk, path, pwd, mbedtls_ctr_drbg_random, drbg);
    }
#endif

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_pk_parse)
{
    mbedtls_pk_context *pk = luaL_checkudata(L, 1, LMBEDTLS_PK_MT);
    int ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    size_t klen = 0, pwdl = 0;
    const unsigned char *key = (const unsigned char *)luaL_checklstring(L, 2, &klen);
    const unsigned char *pwd = NULL;
    int pub = 0;

    if (lua_isstring(L, 3))
    {
        pwd = (const unsigned char *)lua_tolstring(L, 3, &pwdl);
    }
    else
    {
        pub = lua_toboolean(L, 3);
    }

#if defined(MBEDTLS_PK_PARSE_C)
    if (pub)
    {
        ret = mbedtls_pk_parse_public_key(pk, key, klen);
    }
    else
    {
        mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 4, LMBEDTLS_RNG_MT);
        ret = mbedtls_pk_parse_key(pk, key, klen, pwd, pwdl, mbedtls_ctr_drbg_random, drbg);
    }
#endif

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static const char *pk_type[] =
{
    "NONE",
    "RSA",
    "ECKEY",
    "ECKEY_DH",
    "ECDSA",
    "RSA_ALT",
    "RSASSA_PSS",
    "OPAQUE",

    NULL,
};

static LUA_FUNCTION(lmbedtls_pk_new)
{
    const mbedtls_pk_info_t *info = NULL;
    mbedtls_pk_context *pk = NULL;

    luaL_argcheck(L, lua_isnone(L, 1) || lua_isstring(L, 1), 1, "none or string only");

    if (lua_isstring(L, 1))
    {
        const mbedtls_pk_type_t type = luaL_checkoption(L, 1, NULL, pk_type);
        info = mbedtls_pk_info_from_type(type);
        luaL_argcheck(L, info != NULL, 1, strerror(EINVAL));
    }

    pk = lua_newuserdata(L, sizeof(mbedtls_pk_context));
    if (!pk)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_pk_init(pk);
    if (info)
    {
        int ret = mbedtls_pk_setup(pk, info);
        if (ret)
        {
            mbedtls_pk_free(pk);
            return mbedtls_pusherror(L, ret);
        }
    }

    luaL_getmetatable(L, LMBEDTLS_PK_MT);
    lua_setmetatable(L, -2);
    return 1;
}

struct luaL_Reg pk_meta[] =
{
    {"__gc",       lmbedtls_pk_gc},
    {"__tostring", lmbedtls_pk_tostring},

    {NULL,         NULL}
};

struct luaL_Reg pk_methods[] =
{
    {"parsefile",  lmbedtls_pk_parsefile},
    {"parse",      lmbedtls_pk_parse},

    {"cando",      lmbedtls_pk_cando},
    {"encrypt",    lmbedtls_pk_encrypt},
    {"decrypt",    lmbedtls_pk_decrypt},
    {"sign",       lmbedtls_pk_sign},
    {"verify",     lmbedtls_pk_verify},
    {"genkey",     lmbedtls_pk_genkey},
    {"checkpair",  lmbedtls_pk_checkpair},

    {"get",        lmbedtls_pk_get},
    {"write",      lmbedtls_pk_write},

    {NULL,         NULL}
};

struct luaL_Reg pk_libs[] =
{
    {"new",        lmbedtls_pk_new},

    {NULL,         NULL}
};

LUALIB_API int
luaopen_mbedtls_pk(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_PK_MT, pk_meta, pk_methods);

    luaL_newlib(L, pk_libs);
    return 1;
}
