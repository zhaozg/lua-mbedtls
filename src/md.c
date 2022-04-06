#include "mbedtls.h"

static LUA_FUNCTION(lmbedtls_md_finish)
{
    int ret;
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    unsigned char hash[MBEDTLS_MD_MAX_SIZE] = {0};
    const mbedtls_md_info_t *info = mbedtls_md_info_from_ctx(md);
    int hmac = 0;

    lua_pushlightuserdata(L, md);
    lua_rawget(L, LUA_REGISTRYINDEX);
    hmac = lua_toboolean(L,-1);
    lua_pop(L, 1);

    if (hmac)
    {
        ret = mbedtls_md_hmac_finish(md, hash);
        mbedtls_md_hmac_reset(md);
    }
    else
    {
        ret = mbedtls_md_finish(md, hash);
        mbedtls_md_starts(md);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushlstring(L, (const char *)hash, mbedtls_md_get_size(info));
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_update)
{
    int ret;
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    size_t len = 0;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &len);
    int hmac = 0;

    lua_pushlightuserdata(L, md);
    lua_rawget(L, LUA_REGISTRYINDEX);
    hmac = lua_toboolean(L,-1);
    lua_pop(L, 1);

    if (hmac)
    {
        ret = mbedtls_md_hmac_update(md, input, len);
    }
    else
    {
        ret = mbedtls_md_update(md, input, len);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_gc)
{
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    lua_pushlightuserdata(L, md);
    lua_pushnil(L);
    lua_rawset(L, LUA_REGISTRYINDEX);
    mbedtls_md_free(md);
    return 0;
}

static LUA_FUNCTION(lmbedtls_md_clone)
{
    int ret;
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    mbedtls_md_context_t *clone = lua_newuserdata(L, sizeof(mbedtls_md_context_t));

    mbedtls_md_init(clone);
    ret = mbedtls_md_clone(clone, md);
    if (ret)
    {
        mbedtls_md_free(clone);
        return mbedtls_pusherror(L, ret);
    }

    luaL_getmetatable(L, LMBEDTLS_MD_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_size)
{
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_ctx(md);
    lua_pushinteger(L, mbedtls_md_get_size(info));
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_name)
{
    mbedtls_md_context_t *md = luaL_checkudata(L, 1, LMBEDTLS_MD_MT);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_ctx(md);
    lua_pushstring(L, mbedtls_md_get_name(info));
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_new)
{
    int ret;
    size_t len = 0;
    const char *key, *alg;
    const mbedtls_md_info_t *info;
    mbedtls_md_context_t *md;

    alg = luaL_checkstring(L, 1);
    info = mbedtls_md_info_from_string(alg);
    luaL_argcheck(L, info != NULL, 1, strerror(EINVAL));
    key = luaL_checklstring(L, 2, &len);

    md = lua_newuserdata(L, sizeof(mbedtls_md_context_t));

    mbedtls_md_init(md);
    ret = mbedtls_md_setup(md, info,len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    ret = key ? mbedtls_md_hmac_starts(md, (const unsigned char *)key, len)
        : mbedtls_md_starts(md);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushlightuserdata(L, md);
    lua_pushboolean(L, key!=NULL);
    lua_rawset(L, LUA_REGISTRYINDEX);

    luaL_getmetatable(L, LMBEDTLS_MD_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static LUA_FUNCTION(lmbedtls_md_list)
{
    const int *md = mbedtls_md_list();
    const mbedtls_md_info_t *info;
    int i = 1;

    lua_newtable(L);

    while (*md)
    {
        info = mbedtls_md_info_from_type(*md++);
        lua_pushstring(L, mbedtls_md_get_name(info));
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

LUA_FUNCTION(lmbedtls_hash)
{
    int ret;
    size_t size;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const char *alg;
    const unsigned char *data;
    const mbedtls_md_info_t *info;

    alg = luaL_checkstring(L, 1);
    info = mbedtls_md_info_from_string(alg);
    luaL_argcheck(L, info != NULL, 1, strerror(EINVAL));

    data = (const unsigned char *)luaL_checklstring(L, 2, &size);

    ret = mbedtls_md(info, data, size, hash);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)hash, mbedtls_md_get_size(info));
        return 1;
    }
    return mbedtls_pusherror(L, ret);
}

LUA_FUNCTION(lmbedtls_hmac)
{
    int ret;
    size_t klen, size;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const char *alg;
    const unsigned char *key, *data;
    const mbedtls_md_info_t *info;

    alg = luaL_checkstring(L, 1);
    info = mbedtls_md_info_from_string(alg);

    key = (const unsigned char *)luaL_checklstring(L, 2, &klen);
    data = (const unsigned char *)luaL_checklstring(L, 3, &size);

    ret = mbedtls_md_hmac(info, key, klen, data, size, hash);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)hash, mbedtls_md_get_size(info));
        return 1;
    }
    return mbedtls_pusherror(L, ret);
}

LUA_FUNCTION(lmbedtls_md_hash_file)
{
    int ret;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const char *alg;
    const char *infile;
    const mbedtls_md_info_t *info;

    alg = luaL_checkstring(L, 1);
    info = mbedtls_md_info_from_string(alg);
    luaL_argcheck(L, info != NULL, 1, strerror(EINVAL));

    infile = luaL_checkstring(L, 2);

    ret = mbedtls_md_file(info, infile, hash);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)hash, mbedtls_md_get_size(info));
        return 1;
    }
    return mbedtls_pusherror(L, ret);
}

struct luaL_Reg md_libs[] =
{
    {"list",     lmbedtls_md_list},
    {"new",      lmbedtls_md_new},

    {"hash",     lmbedtls_hash},
    {"hmac",     lmbedtls_hmac},

    {"hash_file",lmbedtls_md_hash_file},

    {NULL,       NULL}
};


struct luaL_Reg md_methods[] =
{
    {"update",   lmbedtls_md_update},
    {"finish",   lmbedtls_md_finish},
    {"clone",    lmbedtls_md_clone},
    {"size",     lmbedtls_md_size},
    {"name",     lmbedtls_md_name},

    {NULL,       NULL}
};

struct luaL_Reg md_meta[] =
{
    {"__gc",       lmbedtls_md_gc},
    {"__tostring", mbedtls_tostring},

    {NULL,         NULL}
};


LUALIB_API
LUA_FUNCTION(luaopen_mbedtls_md)
{
    mbedtls_register(L, LMBEDTLS_MD_MT, md_meta, md_methods);

    luaL_newlib(L, md_libs);
    return 1;
}
