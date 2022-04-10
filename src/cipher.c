#include "mbedtls.h"

static const char *cipher_mode[] =
{
    "NONE",                 /**< None.                        */
    "ECB",                  /**< The ECB cipher mode.         */
    "CBC",                  /**< The CBC cipher mode.         */
    "CFB",                  /**< The CFB cipher mode.         */
    "OFB",                  /**< The OFB cipher mode.         */
    "CTR",                  /**< The CTR cipher mode.         */
    "GCM",                  /**< The GCM cipher mode.         */
    "STREAM",               /**< The stream cipher mode.      */
    "CCM",                  /**< The CCM cipher mode.         */
    "CCM_STAR_NO_TAG",      /**< The CCM*-no-tag cipher mode. */
    "XTS",                  /**< The XTS cipher mode.         */
    "CHACHAPOLY",           /**< The ChaCha-Poly cipher mode. */
    "KW",                   /**< The SP800-38F KW mode        */
    "KWP",                  /**< The SP800-38F KWP mode       */

    NULL,
};

static const char *cipher_pad[] =
{
    "PKCS7",       /**< PKCS7 padding (default).        */
    "ONE_AND_ZEROS", /**< ISO/IEC 7816-4 padding.         */
    "ZEROS_AND_LEN", /**< ANSI X.923 padding.             */
    "ZEROS",       /**< Zero padding (not reversible).  */
    "NONE",        /**< Never pad (full blocks only).   */

    NULL,
};

static LUA_FUNCTION(lmbedtls_cipher_checktag)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    int ret;

#if defined(MBEDTLS_GCM_C)
    size_t len = 0;
    const unsigned char *tag = (const unsigned char *)luaL_checklstring(L, 2, &len);
    ret = mbedtls_cipher_check_tag(cph, tag, len);
#else
    ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_cipher_writetag)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    int ret;

#if defined(MBEDTLS_GCM_C)
    size_t len = luaL_checkinteger(L, 2);
    unsigned char tag[MBEDTLS_MAX_BLOCK_LENGTH] = {0};
    ret = mbedtls_cipher_write_tag(cph, tag, len);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)tag, len);
        return 1;
    }
#else  /* if defined(MBEDTLS_GCM_C) */
    ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif
    return mbedtls_pusherror(L, ret);
}

static LUA_FUNCTION(lmbedtls_cipher_finish)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    unsigned char output[MBEDTLS_MAX_BLOCK_LENGTH] = {0};
    size_t len = sizeof(output);

    int ret = mbedtls_cipher_finish(cph, output, &len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushlstring(L, (const char *)output, len);
    return 1;
}

static LUA_FUNCTION(lmbedtls_cipher_update)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    size_t ilen = 0;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    size_t olen = ilen + MBEDTLS_MAX_BLOCK_LENGTH;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_cipher_update(cph, input, ilen, output, &olen);
    if (ret)
    {
        mbedtls_free(output);
        return mbedtls_pusherror(L, ret);
    }
    lua_pushlstring(L, (const char *)output, olen);
    mbedtls_free(output);
    return 1;
}

static LUA_FUNCTION(lmbedtls_cipher_updatead)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
#if defined(MBEDTLS_GCM_C)
    size_t ilen = 0;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    int ret = mbedtls_cipher_update_ad(cph, input, ilen);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
#else  /* if defined(MBEDTLS_GCM_C) */
    return mbedtls_pusherror(L, MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);
#endif
}

static LUA_FUNCTION(lmbedtls_cipher_reset)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    int ret = mbedtls_cipher_reset(cph);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

/*
 * iv:
 * key:
 * pad:
 */
static LUA_FUNCTION(lmbedtls_cipher_set)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    const char *key = luaL_checkstring(L, 2);
    const unsigned char *val;
    int ret = 0;

    size_t len = 0;

    if (strcasecmp(key, "iv")==0)
    {
        val = (const unsigned char *)luaL_checklstring(L, 3, &len);
        ret = mbedtls_cipher_set_iv(cph, val, len);
    }
    else if (strcasecmp(key, "key")==0)
    {
        mbedtls_operation_t op;
        val = (const unsigned char *)luaL_checklstring(L, 3, &len);
        luaL_argcheck(L, lua_type(L, 4)== LUA_TBOOLEAN, 4,
                      "true for encryption, false for decryption");
        op = lua_toboolean(L, 4);

        ret = mbedtls_cipher_setkey(cph, val, len * CHAR_BIT, op);
    }
    else if (strcasecmp(key, "pad")==0)
    {
        mbedtls_cipher_padding_t pad = luaL_checkoption(L, 3, NULL, cipher_pad);
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
        ret = mbedtls_cipher_set_padding_mode(cph, pad);
#else
        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif
    }
    else
    {
        luaL_error(L, "%s: %s", key, strerror(EINVAL));
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

/*
 * operation: true for encryption, false for decryption
 * keylen:
 * name:
 * mode:
 * */
static LUA_FUNCTION(lmbedtls_cipher_get)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    const char *key = luaL_checkstring(L, 2);

    if (strcasecmp(key, "operation")==0)
    {
        mbedtls_operation_t op = mbedtls_cipher_get_operation(cph);
        switch (op)
        {
            case MBEDTLS_OPERATION_NONE:
                lua_pushliteral(L, "NONE");
                break;

            case MBEDTLS_ENCRYPT:
                lua_pushliteral(L, "ENCRYPT");
                break;

            case MBEDTLS_DECRYPT:
                lua_pushliteral(L, "DECRYPT");
                break;

            default:
                lua_pushnil(L);
        }
        return 1;
    }
    else if (strcasecmp(key, "keylen")==0)
    {
        lua_pushinteger(L, mbedtls_cipher_get_key_bitlen(cph)/CHAR_BIT);
        return 1;
    }
    else if (strcasecmp(key, "ivlen")==0)
    {
        lua_pushinteger(L, mbedtls_cipher_get_iv_size(cph));
        return 1;
    }
    else if (strcasecmp(key, "blocksize")==0)
    {
        lua_pushinteger(L, mbedtls_cipher_get_block_size(cph));
        return 1;
    }
    else if (strcasecmp(key, "name")==0)
    {
        const char *name = mbedtls_cipher_get_name(cph);
        lua_pushstring(L, name);
        return 1;
    }
    else if (strcasecmp(key, "mode")==0)
    {
        mbedtls_cipher_mode_t mode = mbedtls_cipher_get_cipher_mode(cph);
        if (mode<SIZE_OF_ARRAY(cipher_mode))
        {
            lua_pushstring(L, cipher_mode[mode]);
        }
        else
        {
            lua_pushinteger(L, mode);
        }
        return 1;
    }
    else
    {
        luaL_error(L, "%s: %s", key, strerror(EINVAL));
    }

    return 0;
}

static LUA_FUNCTION(lmbedtls_cipher_crypt)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    size_t ilen, ivlen;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    const unsigned char *iv = (const unsigned char *)luaL_optlstring(L, 3, NULL, &ivlen);
    size_t olen = ilen + MBEDTLS_MAX_BLOCK_LENGTH;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_cipher_crypt(cph, iv, ivlen, input, ilen, output, &olen);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)output, olen);
        ret = 1;
    }
    else
    {
        ret = mbedtls_pusherror(L, ret);
    }

    mbedtls_free(output);
    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_AEAD) || defined(MBEDTLS_NIST_KW_C)
static LUA_FUNCTION(lmbedtls_cipher_encrypt_ext)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    size_t ilen, ivlen, adlen;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    const unsigned char *iv = (const unsigned char *)luaL_optlstring(L, 3, NULL, &ivlen);
    const unsigned char *ad = (const unsigned char *)luaL_optlstring(L, 4, NULL, &adlen);
    size_t tag_len = luaL_optinteger(L, 5, 0);
    size_t olen = ilen + MBEDTLS_MAX_BLOCK_LENGTH + tag_len;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_cipher_auth_encrypt_ext(cph, iv, ivlen, ad, adlen,
                                              input, ilen,
                                              output, olen, &olen,
                                              tag_len);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)output, olen);
        ret = 1;
    }
    else
    {
        ret = mbedtls_pusherror(L, ret);
    }

    mbedtls_free(output);
    return ret;
}

static LUA_FUNCTION(lmbedtls_cipher_decrypt_ext)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    size_t ilen, ivlen, adlen;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 2, &ilen);
    const unsigned char *iv = (const unsigned char *)luaL_optlstring(L, 3, NULL, &ivlen);
    const unsigned char *ad = (const unsigned char *)luaL_optlstring(L, 4, NULL, &adlen);
    size_t tag_len = luaL_optinteger(L, 5, 0);
    size_t olen = ilen + MBEDTLS_MAX_BLOCK_LENGTH + tag_len;
    unsigned char *output = mbedtls_calloc(1, olen);

    int ret = mbedtls_cipher_auth_decrypt_ext(cph, iv, ivlen, ad, adlen,
                                              input, ilen,
                                              output, olen, &olen,
                                              tag_len);
    if (ret==0)
    {
        lua_pushlstring(L, (const char *)output, olen);
        ret = 1;
    }
    else
    {
        ret = mbedtls_pusherror(L, ret);
    }

    mbedtls_free(output);
    return ret;
}
#endif /* if defined(MBEDTLS_CIPHER_MODE_AEAD) || defined(MBEDTLS_NIST_KW_C) */

static LUA_FUNCTION(lmbedtls_cipher_gc)
{
    mbedtls_cipher_context_t *cph = luaL_checkudata(L, 1, LMBEDTLS_CIPHER_MT);
    mbedtls_cipher_free(cph);
    return 0;
}

static LUA_FUNCTION(lmbedtls_cipher_list)
{
    const int *chp = mbedtls_cipher_list();
    const mbedtls_cipher_info_t *info;
    int i = 1;

    lua_newtable(L);
    while (*chp)
    {
        info = mbedtls_cipher_info_from_type(*chp++);
        lua_pushstring(L, mbedtls_cipher_info_get_name(info));
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

static LUA_FUNCTION(lmbedtls_cipher_new)
{
    const char *alg = luaL_checkstring(L, 1);
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_string(alg);
    mbedtls_cipher_context_t *cph = NULL;
    int ret;

    luaL_argcheck(L, info != NULL, 1, strerror(EINVAL));

    cph = lua_newuserdata(L, sizeof(mbedtls_cipher_context_t));
    if (cph==NULL)
    {
        luaL_error(L, strerror(errno));
    }

    mbedtls_cipher_init(cph);
    ret = mbedtls_cipher_setup(cph, info);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    mbedtls_setmetatable(L, -1, LMBEDTLS_CIPHER_MT, NULL);
    return 1;
}

struct luaL_Reg cipher_libs[] =
{
    {"list",     lmbedtls_cipher_list},
    {"new",      lmbedtls_cipher_new},

    {NULL,       NULL}
};

struct luaL_Reg cipher_meta[] =
{
    {"__gc",       lmbedtls_cipher_gc},
    {"__tostring", mbedtls_tostring},

    {NULL,         NULL}
};

struct luaL_Reg cipher_methods[] =
{
    {"reset",          lmbedtls_cipher_reset},
    {"updatead",       lmbedtls_cipher_updatead},
    {"update",         lmbedtls_cipher_update},
    {"finish",         lmbedtls_cipher_finish},

    {"writetag",       lmbedtls_cipher_writetag},
    {"checktag",       lmbedtls_cipher_checktag},

    {"get",            lmbedtls_cipher_get},
    {"set",            lmbedtls_cipher_set},

    {"crypt",          lmbedtls_cipher_crypt},
#if defined(MBEDTLS_CIPHER_MODE_AEAD) || defined(MBEDTLS_NIST_KW_C)
    {"encrypt",        lmbedtls_cipher_encrypt_ext},
    {"decrypt",        lmbedtls_cipher_decrypt_ext},
#endif

    {NULL, NULL}
};


LUALIB_API int
luaopen_mbedtls_cipher(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_CIPHER_MT, cipher_meta, cipher_methods);

    luaL_newlib(L, cipher_libs);
    return 1;
}
