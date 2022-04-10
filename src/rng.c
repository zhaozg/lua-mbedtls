#include "mbedtls.h"


static LUA_FUNCTION(lmbedtls_rng_random)
{
    int ret;
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    size_t len = luaL_optinteger(L, 2, MBEDTLS_CTR_DRBG_MAX_REQUEST);
    unsigned char output[MBEDTLS_CTR_DRBG_MAX_REQUEST] = {0};
    size_t addlen;
    const unsigned char *additional = (const unsigned char *)luaL_optlstring(L, 3, NULL, &addlen);

    if (len > MBEDTLS_CTR_DRBG_MAX_REQUEST)
    {
        lua_pushfstring(L, "out of range [1, %d]", MBEDTLS_CTR_DRBG_MAX_REQUEST);
        return luaL_argerror(L, 1, lua_tostring(L, -1));
    }

    if (additional)
    {
        ret = mbedtls_ctr_drbg_random_with_add(drbg, output, len, additional, addlen);
    }
    else
    {
        ret = mbedtls_ctr_drbg_random(drbg, output, len);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushlstring(L, (const char *)output, len);
    return 1;
}

static LUA_FUNCTION(lmbedtls_rng_update)
{
    size_t len = 0;
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    const unsigned char *seed = (const unsigned char *)luaL_checklstring(L, 2, &len);

    int ret = mbedtls_ctr_drbg_update(drbg, seed, len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_rng_reseed)
{
    size_t len = 0;
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    const unsigned char *seed = (const unsigned char *)luaL_checklstring(L, 2, &len);

    int ret = mbedtls_ctr_drbg_reseed(drbg, seed, len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_rng_set)
{
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    const char *key = luaL_checkstring(L, 2);

    if (strcasecmp(key, "reseed_interval")==0)
    {
        int itvl = luaL_checkinteger(L, 3);
        mbedtls_ctr_drbg_set_reseed_interval(drbg, itvl);
    }
    else if (strcasecmp(key, "entropy_len")==0)
    {
        int len = luaL_checkinteger(L, 3);
        mbedtls_ctr_drbg_set_entropy_len(drbg, len);
    }
    else if (strcasecmp(key, "nonce_len")==0)
    {
        int len = luaL_checkinteger(L, 3);
        mbedtls_ctr_drbg_set_nonce_len(drbg, len);
    }
    else if (strcasecmp(key, "prediction_resistance")==0)
    {
        int resistance = lua_toboolean(L, 3);
        mbedtls_ctr_drbg_set_prediction_resistance(drbg, resistance);
    }
    else
    {
        luaL_error(L, "NYI");
        return 0;
    }

    lua_pushvalue(L, 1);
    return 1;
}

#if defined(MBEDTLS_FS_IO)
static LUA_FUNCTION(lmbedtls_rng_write_seed_file)
{
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    const char *path = luaL_checkstring(L, 2);

    int ret = mbedtls_ctr_drbg_write_seed_file(drbg, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_rng_update_seed_file)
{
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    const char *path = luaL_checkstring(L, 2);

    int ret = mbedtls_ctr_drbg_update_seed_file(drbg, path);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}
#endif /* if defined(MBEDTLS_FS_IO) */

static LUA_FUNCTION(lmbedtls_rng_gc)
{
    mbedtls_ctr_drbg_context *drbg = luaL_checkudata(L, 1, LMBEDTLS_RNG_MT);
    mbedtls_ctr_drbg_free(drbg);

    return 0;
}

LUA_FUNCTION(lmbedtls_rng_new)
{
    int ret;
    size_t len = 0;
    const unsigned char *seed = (const unsigned char *)luaL_optlstring(L, 1, NULL, &len);

    mbedtls_ctr_drbg_context *drbg = lua_newuserdata(L, sizeof(mbedtls_ctr_drbg_context));
    if (!drbg)
    {
        return luaL_error(L, strerror(errno));
    }
    mbedtls_ctr_drbg_init(drbg);
    ret = mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, &lmbedtls_entropy,
                                seed, len);
    if (ret)
    {
        mbedtls_ctr_drbg_free(drbg);
        return mbedtls_pusherror(L, ret);
    }

    mbedtls_setmetatable(L, -1, LMBEDTLS_RNG_MT, NULL);
    return 1;
}

struct luaL_Reg rng_meta[] =
{
    {"__gc",         lmbedtls_rng_gc},
    {"__tostring",   mbedtls_tostring},

    {NULL,           NULL}
};

struct luaL_Reg rng_methods[] =
{
    {"set",                lmbedtls_rng_set},
    {"reseed",             lmbedtls_rng_reseed},
    {"update",             lmbedtls_rng_update},
#if defined(MBEDTLS_FS_IO)
    {"write_seed_file",    lmbedtls_rng_write_seed_file},
    {"update_seed_file",   lmbedtls_rng_update_seed_file},
#endif
    {"random",             lmbedtls_rng_random},

    {NULL,                 NULL}
};

struct luaL_Reg rng_libs[] =
{
    {"new",    lmbedtls_rng_new},

    {NULL,     NULL}
};

LUALIB_API int
luaopen_mbedtls_rng(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_RNG_MT, rng_meta, rng_methods);

    luaL_newlib(L, rng_libs);
    return 1;
}
