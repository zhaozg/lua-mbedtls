#include "mbedtls.h"

#include "mbedtls/debug.h"

const char *const authmode_lst[] = {"none", "optional", "required", "unset", NULL};

static void
lmbedtls_debug(void *ctx, int level,
               const char *file, int line,
               const char *str )
{
    const char *p, *basename;

    ((void) ctx);
    ((void) level);

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: |%d| %s",
                     basename, line, level, str );
    fflush(  (FILE *) ctx  );
}

static int
lmbedtls_pushsslresult(lua_State *L, int ret)
{
    if (ret>0)
    {
        lua_pushinteger(L, ret);
        return 1;
    }
    else if (ret==0)
    {
        lua_pushboolean(L, ret==0);
        return 1;
    }

    switch (ret)
    {
        case MBEDTLS_ERR_SSL_WANT_READ:
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "WANT_READ");
            return 2;

        case MBEDTLS_ERR_SSL_WANT_WRITE:
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "WANT_WRITE");
            return 2;

        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "IN_PROCESS_ASYNC");
            return 2;

        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "IN_PROCESS_CRYPTO");
            return 2;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "CLOSE_NOTIFY");
            return 2;

        default:
            break;
    }
    return mbedtls_pusherror(L, ret);
}

static int
lmbedtls_ssl_conf_crt_vrfy(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    int ret;
    mbedtls_ssl_config *conf = (mbedtls_ssl_config *)ctx;
    lua_State *L = mbedtls_ssl_conf_get_user_data_p(conf);

    lua_pushlightuserdata(L, conf);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, lmbedtls_ssl_conf_crt_vrfy);
    lua_rawget(L, -2);
    lua_pushlstring(L, (const char *)crt->raw.p, crt->raw.len);
    lua_pushinteger(L, depth);
    lua_pushinteger(L, *flags);

    ret = lua_pcall(L, 3, 2, 0);
    if (ret != LUA_OK)
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        lua_pop(L, 2);
    }
    else
    {
        ret = luaL_optinteger(L, -1, 0);
        *flags = (uint32_t)luaL_optinteger(L, -2, 0);
        lua_pop(L, 3);
    }

    return ret;
}

static LUA_FUNCTION(lmbedtls_session_new)
{
    mbedtls_ssl_session *session = lua_newuserdata(L, sizeof(mbedtls_ssl_session));

    if (!session)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_ssl_session_init(session);

    mbedtls_setmetatable(L, -1, LMBEDTLS_SSL_SESSION_MT, NULL);
    return 1;
}

static LUA_FUNCTION(lmbedtls_session_load)
{
    mbedtls_ssl_session *session = luaL_checkudata(L, 1, LMBEDTLS_SSL_SESSION_MT);
    size_t len;
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &len);

    int ret = mbedtls_ssl_session_load(session, buf, len);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_session_save)
{
    mbedtls_ssl_session *session = luaL_checkudata(L, 1, LMBEDTLS_SSL_SESSION_MT);
    unsigned char buf[4096];
    size_t len = sizeof(buf);
    unsigned char *pbuf = buf;

    int ret = mbedtls_ssl_session_save(session, buf, len, &len);

    if (ret==MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL)
    {
        pbuf = mbedtls_calloc(1, len);
        ret = mbedtls_ssl_session_save(session, pbuf, len,  &len);
    }
    if (ret)
    {
        ret = mbedtls_pusherror(L, ret);
    }
    else
    {
        lua_pushlstring(L, (const char *)pbuf, len);
        ret = 1;
    }
    if (pbuf != buf)
    {
        mbedtls_free(pbuf);
    }
    return ret;
}

static LUA_FUNCTION(lmbedtls_session_gc)
{
    mbedtls_ssl_session *session = luaL_checkudata(L, 1, LMBEDTLS_SSL_SESSION_MT);
    mbedtls_ssl_session_free(session);
    return 0;
}

static luaL_Reg session_methods[] =
{
    {"save",       lmbedtls_session_save},
    {"load",       lmbedtls_session_load},

    {NULL, NULL}
};

static luaL_Reg session_meta[] =
{
    {"__gc",       lmbedtls_session_gc},
    {"__tostring", mbedtls_tostring},

    {NULL, NULL}
};

static LUA_FUNCTION(lmbedtls_ssl_conf_new)
{
    const char *const endpoint_lst[] = {"client", "server", NULL};
    const char *const preset_lst[] = {"default", "suiteb", NULL};

    int endpoint = luaL_checkoption(L, 1, "client", endpoint_lst);
    int transport = luaL_checkoption(L, 2, "tcp", proto_lst);
    int preset = luaL_checkoption(L, 3, "default", preset_lst);
    int ret;

    mbedtls_ssl_config *conf = lua_newuserdata(L, sizeof(mbedtls_ssl_config));

    if (!conf)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_ssl_config_init(conf);

    ret = mbedtls_ssl_config_defaults(conf, endpoint, transport, preset*2);
    if (ret)
    {
        mbedtls_ssl_config_free(conf);
        return mbedtls_pusherror(L, ret);
    }
    mbedtls_ssl_conf_dbg(conf, lmbedtls_debug, stderr);

    mbedtls_ssl_conf_set_user_data_p(conf, L);

    mbedtls_setmetatable(L, -1, LMBEDTLS_SSL_CONFIG_MT, conf);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_conf_set)
{
    mbedtls_ssl_config *conf = luaL_checkudata(L, 1, LMBEDTLS_SSL_CONFIG_MT);
    const char *key = luaL_checkstring(L, 2);
    int ret = 0;

    if (strcasecmp(key, "endpoint")==0)
    {
        if (lua_isboolean(L, 3))
        {
            mbedtls_ssl_conf_endpoint(conf, lua_toboolean(L, 3));
        }
        else
        {
            const char *const lst[] = {"client", "server", NULL};
            int endpoint = luaL_checkoption(L, 3, NULL, lst);
            mbedtls_ssl_conf_endpoint(conf, endpoint);
        }
    }
    else if (strcasecmp(key, "transport")==0)
    {
        int transport = luaL_checkoption(L, 3, NULL, proto_lst);
        mbedtls_ssl_conf_transport(conf, transport);
    }
    else if (strcasecmp(key, "authmode")==0)
    {
        int authmode = luaL_checkoption(L, 3, NULL, authmode_lst);
        mbedtls_ssl_conf_authmode(conf, authmode);
    }
    else if (strcasecmp(key, "rng")==0)
    {
        mbedtls_ctr_drbg_context *rng = luaL_checkudata(L, 3, LMBEDTLS_RNG_MT);
        mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rng);

        lua_pushlightuserdata(L, conf);
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_pushlightuserdata(L, rng);
        lua_pushvalue(L, 3);
        lua_rawset(L, -3);
        lua_pop(L, 1);
    }
    else if (strcasecmp(key, "verify")==0)
    {
        luaL_argcheck(L, lua_type(L, 3)==LUA_TFUNCTION, 3, "only accpet a function to verify cert");

        lua_pushlightuserdata(L, conf);
        lua_rawget(L, LUA_REGISTRYINDEX);

        lua_pushlightuserdata(L, lmbedtls_ssl_conf_crt_vrfy);
        lua_pushvalue(L, 3);
        lua_rawset(L, -3);

        lua_pop(L, 1);

        mbedtls_ssl_conf_verify(conf, lmbedtls_ssl_conf_crt_vrfy, conf);
    }
    else if (strcasecmp(key, "dbg")==0)
    {
        mbedtls_ssl_conf_dbg(conf, lmbedtls_debug, stderr);
    }
    else if (strcasecmp(key, "read_timeout")==0)
    {
        uint32_t timeout = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_read_timeout(conf, timeout);
    }
    else if (strcasecmp(key, "dtls_anti_replay")==0)
    {
        if (lua_isboolean(L, 3))
        {
            mbedtls_ssl_conf_dtls_anti_replay(conf, lua_toboolean(L, 3));
        }
        else
        {
            int mode = luaL_checkoption(L, 3, NULL, switch_lst);
            mbedtls_ssl_conf_dtls_anti_replay(conf, mode);
        }
    }
    else if (strcasecmp(key, "dtls_badmac_limit")==0)
    {
        unsigned dtls_badmac_limit = (unsigned)luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_dtls_badmac_limit(conf, dtls_badmac_limit);
    }
    else if (strcasecmp(key, "handshake_timeout")==0)
    {
        uint32_t min = luaL_checkinteger(L, 3);
        uint32_t max = luaL_checkinteger(L, 4);
        luaL_argcheck(L, min <= max, 4, "max value should not less than min");

        mbedtls_ssl_conf_handshake_timeout(conf, min, max);
    }
    else if (strcasecmp(key, "ciphersuites")==0)
    {
        int i, n, *cip, *pi;
        void *p;
        luaL_argcheck(L, lua_type(L, 3)==LUA_TTABLE, 3, "should be array contains ciphersuite");

        n = lua_rawlen(L, 3);
        cip = (int *)mbedtls_calloc(n+1, sizeof(int));
        memset(cip, 0, (n+1)*sizeof(int));

        for (i = 1, pi = cip; i<=n; i++)
        {
            lua_rawgeti(L, 3, i);
            *pi = mbedtls_ssl_get_ciphersuite_id(lua_tostring(L, -1));
            if (*pi)
            {
                pi++;
            }
        }
        lua_pushlightuserdata(L, conf);
        lua_rawget(L, LUA_REGISTRYINDEX);

        lua_pushliteral(L, "ciphersuites");
        lua_rawget(L, -2);
        p = lua_touserdata(L, -1);
        if (p)
        {
            mbedtls_free(p);
        }
        lua_pop(L, 1);

        lua_pushliteral(L, "ciphersuites");
        lua_pushlightuserdata(L, cip);
        lua_rawset(L, -3);
        lua_pop(L, 1);

        mbedtls_ssl_conf_ciphersuites(conf, cip);
    }
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    else if (strcasecmp(key, "cid")==0)
    {
        luaL_error(L, "NYI");

        /*int mbedtls_ssl_conf_cid(mbedtls_ssl_config *conf, size_t len, int ignore_other_cids); */
    }
#endif
    else if (strcasecmp(key, "cert_profile")==0)
    {
        luaL_error(L, "NYI");

        /*void mbedtls_ssl_conf_cert_profile(mbedtls_ssl_config *conf, */
        /*                                const mbedtls_x509_crt_profile *profile); */
    }
    else if (strcasecmp(key, "ca_chain")==0)
    {
        mbedtls_x509_crt *chains = luaL_checkudata(L, 3, LMBEDTLS_X509_CRT_MT);
        mbedtls_x509_crl *ca_crl = lua_isnone(L, 4) ? NULL
                                 : luaL_checkudata(L, 4, LMBEDTLS_X509_CRL_MT);
        mbedtls_ssl_conf_ca_chain(conf, chains, ca_crl);

        lua_pushlightuserdata(L, conf);
        lua_rawget(L, LUA_REGISTRYINDEX);
        if (chains)
        {
            lua_pushlightuserdata(L, chains);
            lua_pushvalue(L, 3);
            lua_rawset(L, -3);
        }
        if (ca_crl)
        {
            lua_pushlightuserdata(L, ca_crl);
            lua_pushvalue(L, 4);
            lua_rawset(L, -3);
        }
        lua_pop(L, 1);
    }
    else if (strcasecmp(key, "own_cert")==0)
    {
        mbedtls_x509_crt *own_cert = luaL_checkudata(L, 3, LMBEDTLS_X509_CRT_MT);
        mbedtls_pk_context *pk_key = luaL_checkudata(L, 4, LMBEDTLS_PK_MT);
        ret = mbedtls_ssl_conf_own_cert(conf, own_cert, pk_key);

        lua_pushlightuserdata(L, conf);
        lua_rawget(L, LUA_REGISTRYINDEX);
        if (own_cert)
        {
            lua_pushlightuserdata(L, own_cert);
            lua_pushvalue(L, 3);
            lua_rawset(L, -3);
        }
        if (pk_key)
        {
            lua_pushlightuserdata(L, pk_key);
            lua_pushvalue(L, 4);
            lua_rawset(L, -3);
        }
        lua_pop(L, 1);
    }
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    else if (strcasecmp(key, "psk")==0)
    {
        size_t psk_len, psk_identity_len;
        const unsigned char *psk = (const unsigned char *)luaL_checklstring(L, 3, &psk_len);
        const unsigned char *psk_identity =
            (const unsigned char *)luaL_checklstring(L, 4, &psk_identity_len);

        ret = mbedtls_ssl_conf_psk(conf, psk, psk_len, psk_identity, psk_identity_len);
    }
#endif
#if defined(MBEDTLS_DHM_C)
    else if (strcasecmp(key, "dh_param_bin")==0)
    {
        size_t P_len, G_len;
        const unsigned char *dhm_P = (const unsigned char *)luaL_checklstring(L, 3, &P_len);
        const unsigned char *dhm_G =
            (const unsigned char *)luaL_checklstring(L, 4, &G_len);

        ret = mbedtls_ssl_conf_dh_param_bin(conf, dhm_P, P_len, dhm_G, G_len);
    }
    else if (strcasecmp(key, "dhm_min_bitlen")==0)
    {
        size_t bitlen = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_dhm_min_bitlen(conf, bitlen);
    }
#endif
    else if (strcasecmp(key, "groups")==0)
    {
        luaL_error(L, "NYI");
        /*void mbedtls_ssl_conf_groups(mbedtls_ssl_config *conf, const uint16_t *groups); */
    }
    else if (strcasecmp(key, "sig_hashes")==0)
    {
        luaL_error(L, "NYI");
        /*void mbedtls_ssl_conf_sig_hashes(mbedtls_ssl_config *conf, const int *hashes); */
    }
    else if (strcasecmp(key, "sig_algs")==0)
    {
        luaL_error(L, "NYI");
        /*void mbedtls_ssl_conf_sig_algs(mbedtls_ssl_config *conf, const uint16_t* sig_algs); */
    }

    else if (strcasecmp(key, "sni")==0)
    {
        luaL_error(L, "NYI");
        /*
         * void mbedtls_ssl_conf_sni(mbedtls_ssl_config *conf,
         *              int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char *,
         *                           size_t),
         *              void *p_sni);
         */
    }
#if defined(MBEDTLS_SSL_ALPN)
    else if (strcasecmp(key, "sni")==0)
    {
        luaL_error(L, "NYI");
        /*int mbedtls_ssl_conf_alpn_protocols(mbedtls_ssl_config *conf, const char **protos); */
    }
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    else if (strcasecmp(key, "srtp_mki")==0)
    {
        int support_mki_value = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_srtp_mki_value_supported(conf, support_mki_value);
    }
#endif
    else if (strcasecmp(key, "max_tls_version")==0)
    {
        int ver = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_max_tls_version(conf, ver);
    }
    else if (strcasecmp(key, "min_tls_version")==0)
    {
        int ver = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_min_tls_version(conf, ver);
    }
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    else if (strcasecmp(key, "encrypt_then_mac")==0)
    {
        char etm = (char)luaL_checkoption(L, 3, NULL, switch_lst);

        mbedtls_ssl_conf_encrypt_then_mac(conf, etm);
    }
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    else if (strcasecmp(key, "extended_master_secret")==0)
    {
        char ems = (char)luaL_checkoption(L, 3, NULL, switch_lst);

        mbedtls_ssl_conf_extended_master_secret(conf, ems);
    }
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    else if (strcasecmp(key, "cert_req_ca_list")==0)
    {
        char req = (char)luaL_checkoption(L, 3, NULL, switch_lst);

        mbedtls_ssl_conf_cert_req_ca_list(conf, req);
    }
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    else if (strcasecmp(key, "max_frag_len")==0)
    {
        unsigned char req = (unsigned char)luaL_checkinteger(L, 3);
        ret = mbedtls_ssl_conf_max_frag_len(conf, req);
    }
    else if (strcasecmp(key, "preference_order")==0)
    {
        const char *const lst[] = {"server", "client", NULL};
        char order = (char)luaL_checkoption(L, 3, NULL, lst);
        mbedtls_ssl_conf_preference_order(conf, order);
    }
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    else if (strcasecmp(key, "session_tickets")==0)
    {
        int use_tickets = (char)luaL_checkoption(L, 3, NULL, switch_lst);
        mbedtls_ssl_conf_session_tickets(conf, use_tickets);
    }
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    else if (strcasecmp(key, "renegotiation")==0)
    {
        int renegotiation = (char)luaL_checkoption(L, 3, NULL, switch_lst);
        mbedtls_ssl_conf_renegotiation(conf, renegotiation);
    }
    else if (strcasecmp(key, "renegotiation_enforced")==0)
    {
        int max_records = luaL_checkinteger(L, 3);
        mbedtls_ssl_conf_renegotiation_enforced(conf, max_records);
    }
    else if (strcasecmp(key, "renegotiation_period")==0)
    {
        size_t sz;
        const unsigned char *data =
            (const unsigned char *)luaL_checklstring(L, 3, &sz);
        luaL_argcheck(L, sz==8, 3, "limit 8 bytes");

        mbedtls_ssl_conf_renegotiation_period(conf, data);
    }
#endif /* if defined(MBEDTLS_SSL_RENEGOTIATION) */
#if defined(MBEDTLS_SSL_PROTO_CNTLS1_1)
    else if (strstr(key, "cntls") || strstr(key, "CNTLS") )
    {
        ret = mbedtls_ssl_config_cntls(conf);
    }
#endif
    else
    {
        luaL_error(L, "NYI (%s) not support", key);
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_conf_get)
{
    mbedtls_ssl_config *conf = luaL_checkudata(L, 1, LMBEDTLS_SSL_CONFIG_MT);
    const char *key = luaL_checkstring(L, 2);
    (void)conf;
    (void)key;
/*const char *mbedtls_ssl_get_alpn_protocol(const mbedtls_ssl_context *ssl); */
    return 0;
}

static LUA_FUNCTION(lmbedtls_ssl_conf_gc)
{
    void *p;
    mbedtls_ssl_config *conf = luaL_checkudata(L, 1, LMBEDTLS_SSL_CONFIG_MT);

    lua_pushlightuserdata(L, conf);
    lua_rawget(L,LUA_REGISTRYINDEX);

    lua_pushliteral(L, "ciphersuites");
    lua_rawget(L, -2);
    p = lua_touserdata(L, -1);
    if (p)
    {
        mbedtls_free(p);
    }
    lua_pop(L, 2);

    lua_pushlightuserdata(L, conf);
    lua_pushnil(L);
    lua_rawset(L,LUA_REGISTRYINDEX);

    mbedtls_ssl_config_free(conf);
    return 0;
}

static luaL_Reg config_methods[] =
{
    {"set",          lmbedtls_ssl_conf_set},
    {"get",          lmbedtls_ssl_conf_get},

    {NULL, NULL}
};

static luaL_Reg config_meta[] =
{
    {"__gc",         lmbedtls_ssl_conf_gc},
    {"__tostring",   mbedtls_tostring},

    {NULL, NULL}
};

static LUA_FUNCTION(lmbedtls_ssl_ciphersuites)
{
    int i;
    const int *cip = mbedtls_ssl_list_ciphersuites();

    lua_newtable(L);
    for (i = 1; cip; i++, cip++)
    {
        lua_pushstring(L, mbedtls_ssl_get_ciphersuite_name(*cip));
        lua_rawseti(L, -2, i);
    }
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_new)
{
    mbedtls_ssl_context *ssl = lua_newuserdata(L, sizeof(mbedtls_ssl_context));
    if (!ssl)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_ssl_init(ssl);

    mbedtls_ssl_set_user_data_p(ssl, L);

    mbedtls_setmetatable(L, -1, LMBEDTLS_SSL_MT, ssl);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_setup)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    const mbedtls_ssl_config *conf =
        (const mbedtls_ssl_config *)luaL_checkudata(L, 2, LMBEDTLS_SSL_CONFIG_MT);
    int ret = mbedtls_ssl_setup(ssl, conf);

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushlightuserdata(L, ssl);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, (void *)conf);
    lua_pushvalue(L, 2);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_reset)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);

    int ret = mbedtls_ssl_session_reset(ssl);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_get)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);

    const char *key = luaL_checkstring(L, 2);
    int ret = 0;

    if (strcasecmp(key, "bytes_avail")==0)
    {
        lua_pushinteger(L, mbedtls_ssl_get_bytes_avail(ssl));
        return 1;
    }
    else if (strcasecmp(key, "verify_result")==0)
    {
        lua_pushinteger(L, mbedtls_ssl_get_verify_result(ssl));
        return 1;
    }
    else if (strcasecmp(key, "ciphersuite")==0)
    {
        lua_pushstring(L, mbedtls_ssl_get_ciphersuite(ssl));
        return 1;
    }
    else if (strcasecmp(key, "version_number")==0)
    {
        lua_pushstring(L, mbedtls_ssl_get_version(ssl));
        return 1;
    }
    else if (strcasecmp(key, "record_expansion")==0)
    {
        lua_pushboolean(L, mbedtls_ssl_get_record_expansion(ssl));
        return 1;
    }
    else if (strcasecmp(key, "in_record_payload")==0)
    {
        lua_pushinteger(L, mbedtls_ssl_get_max_in_record_payload(ssl));
        return 1;
    }
    else if (strcasecmp(key, "out_record_payload")==0)
    {
        lua_pushinteger(L, mbedtls_ssl_get_max_out_record_payload(ssl));
        return 1;
    }
    else if (strcasecmp(key, "peer_cert")==0)
    {
        const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(ssl);
        if (peer)
        {
            lua_pushlstring(L, (const char *)peer->raw.p, peer->raw.len);
        }
        else
        {
            lua_pushnil(L);
        }
        return 1;
    }
    else if (strcasecmp(key, "session")==0)
    {
        mbedtls_ssl_session *session = lua_newuserdata(L, sizeof(mbedtls_ssl_session));
        if (!session)
        {
            return luaL_error(L, strerror(errno));
        }

        mbedtls_ssl_session_init(session);
        ret = mbedtls_ssl_get_session(ssl, session);
        if (ret)
        {
            mbedtls_ssl_session_free(session);
            return mbedtls_pusherror(L, ret);
        }

        mbedtls_setmetatable(L, -1, LMBEDTLS_SSL_SESSION_MT, NULL);
        return 1;
    }
    else
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (strcasecmp(key, "peer_cid")==0)
    {
        int enabled;
        unsigned char peer_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ] = {0};
        size_t peer_cid_len = sizeof(peer_cid);

        int ret = mbedtls_ssl_get_peer_cid(ssl, &enabled, peer_cid, &peer_cid_len);
        if (ret==0)
        {
            lua_pushboolean(L, enabled);
            lua_pushlstring(L, (const char*)peer_cid, peer_cid_len);
            return 2;
        }
    }
    else
#endif
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
#if MBEDTLS_VERSION_NUMBER  > 0x03010000
    if (strcasecmp(key, "hs_sni")==0)
    {
        size_t name_len;
        const unsigned char *hostname = mbedtls_ssl_get_hs_sni(ssl, &name_len);
        if (hostname)
        {
            lua_pushlstring(L, (const char *)hostname, name_len);
        }
        else
        {
            lua_pushnil(L);
        }
        return 1;
    }
    else
#endif
#endif
    {
        lua_pushlightuserdata(L, ssl);
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_pushstring(L, key);
        lua_rawget(L, -2);

        return 1;
    }
    return mbedtls_pusherror(L, ret);
}

const static int bio_ctx;

static int
lmbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    int ret;
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)ctx;
    lua_State *L = mbedtls_ssl_get_user_data_p(ssl);

    lua_pushlightuserdata(L, ssl);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, lmbedtls_ssl_send);
    lua_rawget(L, -2);

    lua_pushlightuserdata(L, (void *)&bio_ctx);
    lua_rawget(L, -3);

    lua_pushlstring(L, (const char *)buf, len);

    ret = lua_pcall(L, 2, 1, 0);
    if (ret != LUA_OK)
    {
        ret = MBEDTLS_ERR_NET_SEND_FAILED;
    }
    else
    {
        ret = lua_tointeger(L, -1);
    }

    lua_pop(L, 2);
    return ret;

}
static int
lmbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret;
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)ctx;
    lua_State *L = mbedtls_ssl_get_user_data_p(ssl);

    lua_pushlightuserdata(L, ssl);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, lmbedtls_ssl_recv);
    lua_rawget(L, -2);

    lua_pushlightuserdata(L, (void *)&bio_ctx);
    lua_rawget(L, -3);

    lua_pushinteger(L, len);

    ret = lua_pcall(L, 2, 1, 0);
    if (ret != LUA_OK)
    {
        ret = MBEDTLS_ERR_NET_RECV_FAILED;
    }
    else
    {
        if (lua_isnumber(L, -1))
        {
            ret = lua_tointeger(L, -1);
        }
        else
        {
            ret = lua_rawlen(L, -1);
            memcpy(buf, lua_tostring(L, -1), ret);
        }
    }

    lua_pop(L, 2);

    return ret;

}
static int
lmbedtls_ssl_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                          uint32_t timeout)
{
    int ret;
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)ctx;
    lua_State *L = mbedtls_ssl_get_user_data_p(ssl);

    lua_pushlightuserdata(L, ssl);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, lmbedtls_ssl_recv_timeout);
    lua_rawget(L, -2);

    lua_pushlightuserdata(L, (void *)&bio_ctx);
    lua_rawget(L, -3);

    lua_pushinteger(L, len);
    lua_pushinteger(L, timeout);

    ret = lua_pcall(L, 3, 1, 0);
    if (ret != LUA_OK)
    {
        ret = MBEDTLS_ERR_NET_RECV_FAILED;
    }
    else
    {
        if (lua_isnumber(L, -1))
        {
            ret = lua_tointeger(L, -1);
        }
        else
        {
            ret = lua_rawlen(L, -1);
            memcpy(buf, lua_tostring(L, -1), ret);
        }
    }

    lua_pop(L, 2);

    return ret;
}

static int
lmbedtls_ssl_crt_vrfy(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    int ret;
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)ctx;
    lua_State *L = mbedtls_ssl_get_user_data_p(ssl);

    lua_pushlightuserdata(L, ssl);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, lmbedtls_ssl_crt_vrfy);
    lua_rawget(L, -2);
    lua_pushlstring(L, (const char *)crt->raw.p, crt->raw.len);
    lua_pushinteger(L, depth);

    ret = lua_pcall(L, 2, 1, 0);
    if (ret != LUA_OK)
    {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    else
    {
        *flags = (uint32_t)lua_tonumber(L, -1);
    }
    lua_pop(L, 2);

    return ret;
}

static LUA_FUNCTION(lmbedtls_ssl_set)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    const char *key = luaL_checkstring(L, 2);
    int ret = 0;

    if (strcasecmp(key, "bio")==0)
    {
        mbedtls_ssl_context *net = luaL_testudata(L, 3, LMBEDTLS_NET_MT);
        if (net)
        {
            mbedtls_ssl_set_bio(ssl, net,
                                mbedtls_net_send,
                                mbedtls_net_recv,
                                mbedtls_net_recv_timeout);

            lua_pushlightuserdata(L, ssl);
            lua_rawget(L, LUA_REGISTRYINDEX);
            lua_pushlightuserdata(L, net);
            lua_pushvalue(L, 3);
            lua_rawset(L, -3);
            lua_pop(L, 1);
        }
        else
        {
            luaL_argcheck(L, !lua_isnoneornil(L, 3), 3, "must not be none or nil");
            luaL_argcheck(L, lua_isfunction(L, 4), 4, "must be function");
            luaL_argcheck(L, lua_isnoneornil(L, 5) || lua_isfunction(L, 5),
                          5, "must be function or nil");
            luaL_argcheck(L, lua_isnoneornil(L, 6) || lua_isfunction(L, 6),
                          6, "must be function or nil");
            luaL_argcheck(L, lua_isfunction(L, 5) || lua_isfunction(L, 6),
                          6, "must set recv or recv_timeout callback function");

            lua_pushlightuserdata(L, ssl);
            lua_rawget(L, LUA_REGISTRYINDEX);

            lua_pushlightuserdata(L, (void *)&bio_ctx);
            lua_pushvalue(L, 3);
            lua_rawset(L, -3);

            lua_pushlightuserdata(L, lmbedtls_ssl_send);
            lua_pushvalue(L, 4);
            lua_rawset(L, -3);

            lua_pushlightuserdata(L, lmbedtls_ssl_recv);
            lua_pushvalue(L, 5);
            lua_rawset(L, -3);

            lua_pushlightuserdata(L, lmbedtls_ssl_recv_timeout);
            lua_pushvalue(L, 6);
            lua_rawset(L, -3);

            lua_pop(L, 1);

            mbedtls_ssl_set_bio(ssl, ssl,
                                lmbedtls_ssl_send,
                                lua_isnoneornil(L, 5) ? NULL : lmbedtls_ssl_recv,
                                lua_isnoneornil(L, 6) ? NULL : lmbedtls_ssl_recv_timeout);
        }
    }
    else if (strcasecmp("key", "timer")==0)
    {
/*
 * typedef void mbedtls_ssl_set_timer_t(void * ctx,
 *                                    uint32_t int_ms,
 *                                    uint32_t fin_ms);
 * typedef int mbedtls_ssl_get_timer_t(void * ctx);
 */
        luaL_error(L, "NYI");
    }
    else
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (strcasecmp(key, "cid")==0)
    {
        int enable = lua_toboolean(L, 3);
        size_t own_cid_len;
        const unsigned char *own_cid = (const unsigned char*)luaL_checklstring(L, 4, &own_cid_len);
        ret = mbedtls_ssl_set_cid(ssl, enable, own_cid, own_cid_len);
    }
    else
#endif
    if (strcasecmp(key, "mtu")==0)
    {
        uint16_t mtu = luaL_checkinteger(L, 3);
        mbedtls_ssl_set_mtu(ssl, mtu);
        ret = 0;
    }
    else
#endif
    if (strcasecmp(key, "verify")==0)
    {
        luaL_argcheck(L, lua_type(L, 3)==LUA_TFUNCTION, 3, "only accpet a function to verify cert");

        lua_pushlightuserdata(L, ssl);
        lua_rawget(L, LUA_REGISTRYINDEX);

        lua_pushlightuserdata(L, lmbedtls_ssl_crt_vrfy);
        lua_pushvalue(L, 3);
        lua_rawset(L, -3);

        lua_pop(L, 1);

        mbedtls_ssl_set_verify(ssl, lmbedtls_ssl_crt_vrfy, ssl);
    }
    else if (strcasecmp(key, "hs_psk")==0)
    {
        size_t psk_len;
        const unsigned char *psk = (const unsigned char *)luaL_checklstring(L, 3, &psk_len);

        ret = mbedtls_ssl_set_hs_psk(ssl, psk, psk_len);
    }
    else if (strcasecmp(key, "hostname")==0)
    {
        const char *hostname = luaL_checkstring(L, 3);
        ret = mbedtls_ssl_set_hostname(ssl, hostname);
    }
    else
    {
        lua_pushlightuserdata(L, ssl);
        lua_rawget(L, LUA_REGISTRYINDEX);

        lua_pushstring(L, key);
        lua_pushvalue(L, 3);
        lua_rawset(L, -3);

        lua_pop(L, 1);
        ret = 0;
    }

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }

    lua_pushvalue(L, 1);
    return 1;
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
static LUA_FUNCTION(lmbedtls_ssl_check_record)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    size_t blen;
    unsigned char *buf = (unsigned char *)luaL_checklstring(L, 2, &blen);
    int ret = mbedtls_ssl_check_record(ssl, buf, blen);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}
#endif

static LUA_FUNCTION(lmbedtls_ssl_check_pending)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    lua_pushboolean(L, mbedtls_ssl_check_pending(ssl));
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_handshake)
{
    int ret;
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    int step = lua_toboolean(L, 2);

    if (step)
    {
        ret = mbedtls_ssl_handshake_step(ssl);
    }
    else
    {
        ret = mbedtls_ssl_handshake(ssl);
    }

    if (ret)
    {
        return lmbedtls_pushsslresult(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_renegotiate)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    int ret = mbedtls_ssl_renegotiate(ssl);

    if (ret)
    {
        return lmbedtls_pushsslresult(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_read)
{
    int ret;
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    unsigned char buf[4096];
    unsigned char *pbuf = buf;
    size_t len = luaL_optinteger(L, 2, mbedtls_ssl_get_bytes_avail(ssl));

    if (len == 0)
    {
        len = sizeof(buf);
    }

    if (len > sizeof(buf))
    {
        pbuf = mbedtls_calloc(1, len);
    }

    ret = mbedtls_ssl_read(ssl, pbuf, len);

    if (ret>0)
    {
        lua_pushlstring(L, (const char *)pbuf, ret);
        ret = 1;
    } else if (ret==0)
    {
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "CLOSE_INTERNAL");
        return 2;
    }
    else
    {
        ret = lmbedtls_pushsslresult(L, ret);
    }

    if (buf != pbuf)
    {
        mbedtls_free(pbuf);
    }
    return ret;
}

static LUA_FUNCTION(lmbedtls_ssl_write)
{
    size_t len;
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &len);

    int ret = mbedtls_ssl_write(ssl, buf, len);
    if (ret>=0)
    {
        lua_pushnumber(L, ret);
        ret = 1;
    }
    else
    {
        ret = lmbedtls_pushsslresult(L, ret);
    }

    return ret;
}

static LUA_FUNCTION(lmbedtls_ssl_send_alert_message)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    unsigned char level = (unsigned char)luaL_checkinteger(L, 2);
    unsigned char message = (unsigned char)luaL_checkinteger(L, 3);

    int ret = mbedtls_ssl_send_alert_message(ssl, level, message);
    if (ret>=0)
    {
        lua_pushnumber(L, ret);
        ret = 1;
    }
    else
    {
        ret = lmbedtls_pushsslresult(L, ret);
    }

    return ret;
}

static LUA_FUNCTION(lmbedtls_ssl_close_notify)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    int ret =  mbedtls_ssl_close_notify(ssl);
    if (ret)
    {
        return lmbedtls_pushsslresult(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_is_handshake_over)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    lua_pushboolean(L, mbedtls_ssl_is_handshake_over(ssl));
    return 1;
}

static LUA_FUNCTION(lmbedtls_ssl_gc)
{
    mbedtls_ssl_context *ssl = luaL_checkudata(L, 1, LMBEDTLS_SSL_MT);
    luaL_unref(L, LUA_REGISTRYINDEX, mbedtls_ssl_get_user_data_n(ssl));

    mbedtls_ssl_free(ssl);
    return 0;
}

static luaL_Reg ssl_methods[] =
{
    {"setup",               lmbedtls_ssl_setup},
    {"reset",               lmbedtls_ssl_reset},
    {"get",                 lmbedtls_ssl_get},
    {"set",                 lmbedtls_ssl_set},
    {"check_record",        lmbedtls_ssl_check_record},
    {"check_pending",       lmbedtls_ssl_check_pending},
    {"handshake",           lmbedtls_ssl_handshake},
    {"renegotiate",         lmbedtls_ssl_renegotiate},
    {"read",                lmbedtls_ssl_read},
    {"write",               lmbedtls_ssl_write},
    {"is_handshake_over",   lmbedtls_ssl_is_handshake_over},
    {"send_alert_message",  lmbedtls_ssl_send_alert_message},
    {"close_notify",        lmbedtls_ssl_close_notify},

    {NULL, NULL}
};

static luaL_Reg ssl_meta[] =
{
    {"__gc",         lmbedtls_ssl_gc},
    {"__tostring",   mbedtls_tostring},
    {NULL, NULL}
};

static luaL_Reg ssl_libs[] =
{
    {"session_new",  lmbedtls_session_new},
    {"config_new",   lmbedtls_ssl_conf_new},
    {"ssl_new",      lmbedtls_ssl_new},
    {"ciphersuites", lmbedtls_ssl_ciphersuites},

    {NULL, NULL}
};

LUA_API int
luaopen_mbedtls_ssl(lua_State *L)
{
    mbedtls_register(L, LMBEDTLS_SSL_SESSION_MT, session_meta, session_methods);
    mbedtls_register(L, LMBEDTLS_SSL_CONFIG_MT, config_meta, config_methods);
    mbedtls_register(L, LMBEDTLS_SSL_MT, ssl_meta, ssl_methods);

    luaL_newlib(L, ssl_libs);

#define PUSH_ENUM(x)                        \
    lua_pushstring(L, #x);                  \
    lua_pushinteger(L, MBEDTLS_ERR_SSL_ ## x); \
    lua_rawset(L, -3)

    PUSH_ENUM(WANT_READ);
    PUSH_ENUM(WANT_WRITE);
    PUSH_ENUM(TIMEOUT);
    PUSH_ENUM(CONN_EOF);
    PUSH_ENUM(PEER_CLOSE_NOTIFY);

#undef PUSH_ENUM

    return 1;
}
