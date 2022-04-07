#include "mbedtls.h"

static LUA_FUNCTION(lmbedtls_net_new)
{
    mbedtls_net_context *net = lua_newuserdata(L, sizeof(mbedtls_net_context));

    if (!net)
    {
        return luaL_error(L, strerror(errno));
    }

    mbedtls_net_init(net);
    luaL_getmetatable(L, LMBEDTLS_NET_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_connect)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    const char *host = luaL_checkstring(L, 2);
    const char *port = luaL_checkstring(L, 3);
    int proto = luaL_checkoption(L, 4, "tcp", proto_lst);

    int ret = mbedtls_net_connect(net, host, port, proto);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_bind)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    const char *host = luaL_checkstring(L, 2);
    const char *port = luaL_checkstring(L, 3);
    int proto = luaL_checkoption(L, 4, "tcp", proto_lst);

    int ret = mbedtls_net_bind(net, host, port, proto);
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_accept)
{
    int ret;
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    char ip[64] = {0};
    size_t iplen = sizeof(ip);

    mbedtls_net_context *cli = lua_newuserdata(L, sizeof(mbedtls_net_context));
    if (!cli)
    {
        return luaL_error(L, strerror(errno));
    }
    mbedtls_net_init(cli);

    ret = mbedtls_net_accept(net, cli, ip, iplen, &iplen);
    if (ret)
    {
        mbedtls_net_free(cli);
        return mbedtls_pusherror(L, ret);
    }

    luaL_getmetatable(L, LMBEDTLS_NET_MT);
    lua_setmetatable(L, -2);

    lua_pushlstring(L, ip, iplen);

    return 2;
}

static LUA_FUNCTION(lmbedtls_net_poll)
{
    int ret;

    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    uint32_t rw = luaL_checkoption(L, 2, "both", event_lst);
    uint32_t timeout = luaL_optinteger(L, 3, -1);

    if (rw==0)
    {
        rw = 3;
    }
    ret = mbedtls_net_poll(net, rw, timeout);

    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_block)
{
    int ret;

    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    int block = lua_toboolean(L, 2);
    if (block)
    {
        ret = mbedtls_net_set_block(net);
    }
    else
    {
        ret = mbedtls_net_set_nonblock(net);
    }
    if (ret)
    {
        return mbedtls_pusherror(L, ret);
    }
    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_usleep)
{
    unsigned long usec = luaL_checkinteger(L, 1);

    mbedtls_net_usleep(usec);

    lua_pushvalue(L, 1);
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_recv)
{
    int ret;
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    unsigned char buf[4096];
    unsigned char *pbuf = buf;
    size_t len = luaL_optinteger(L, 2, sizeof(buf));
    uint32_t timeout = luaL_optinteger(L, 3, 0);

    if (len > sizeof(buf))
    {
        pbuf = mbedtls_calloc(1, len);
    }

    if (timeout==0)
    {
        ret = mbedtls_net_recv(net, pbuf, len);
    }
    else
    {
        ret = mbedtls_net_recv_timeout(net, pbuf, len, timeout);
    }

    if (ret>=0)
    {
        lua_pushlstring(L, (const char *)pbuf, ret);
        ret = 1;
    }
    else
    {
        ret = mbedtls_pusherror(L, ret);
    }
    if (buf != pbuf)
    {
        mbedtls_free(pbuf);
    }
    return ret;
}

static LUA_FUNCTION(lmbedtls_net_send)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    size_t len;
    const unsigned char *buf = (const unsigned char *)luaL_checklstring(L, 2, &len);

    int ret = mbedtls_net_send(net, buf, len);
    if (ret>=0)
    {
        lua_pushnumber(L, ret);
        ret = 1;
    }
    else
    {
        ret = mbedtls_pusherror(L, ret);
    }

    return ret;
}

static LUA_FUNCTION(lmbedtls_net_fd)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    if (lua_isnone(L, 2))
    {
        lua_pushinteger(L, net->fd);
    } else
    {
        int fd = luaL_checkinteger(L, 2);
        luaL_argcheck(L, net->fd==-1, 1, "must be unused");
        net->fd = fd;
        lua_pushvalue(L, 1);
    }
    return 1;
}

static LUA_FUNCTION(lmbedtls_net_close)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    mbedtls_net_close(net);
    return 0;
}

static LUA_FUNCTION(lmbedtls_net_gc)
{
    mbedtls_net_context *net = luaL_checkudata(L, 1, LMBEDTLS_NET_MT);
    mbedtls_net_close(net);
    mbedtls_net_free(net);
    return 0;
}


struct luaL_Reg net_libs[] =
{
    {"usleep",   lmbedtls_net_usleep},
    {"new",      lmbedtls_net_new},

    {NULL,       NULL}
};


struct luaL_Reg net_methods[] =
{
    {"connect",  lmbedtls_net_connect},
    {"bind",     lmbedtls_net_bind},
    {"accept",   lmbedtls_net_accept},
    {"poll",     lmbedtls_net_poll},
    {"block",    lmbedtls_net_block},
    {"recv",     lmbedtls_net_recv},
    {"send",     lmbedtls_net_send},
    {"close",    lmbedtls_net_close},

    {"fd",       lmbedtls_net_fd},

    {NULL,       NULL}
};

struct luaL_Reg net_meta[] =
{
    {"__gc",       lmbedtls_net_gc},
    {"__tostring", mbedtls_tostring},

    {NULL,         NULL}
};


LUALIB_API
LUA_FUNCTION(luaopen_mbedtls_net)
{
    mbedtls_register(L, LMBEDTLS_NET_MT, net_meta, net_methods);

    luaL_newlib(L, net_libs);
    return 1;
}
