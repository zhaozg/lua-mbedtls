local mbedtls = require("mbedtls")
package.path = "spec/?.lua;" .. package.path

local data = require("data")

local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng

local pk = mbedtls.pk
local crt = mbedtls.crt

--mbedtls.debug_set_threshold("verbose")
rng = assert(rng.new())

local WANT_READ, WANT_WRITE, CONN_EOF = ssl.WANT_READ, ssl.WANT_WRITE, ssl.CONN_EOF
-----------------------------------------------------------------------------

local function create_ssl_conf(mode)
    assert(mode == "server" or mode == "client")
    local conf = assert(ssl.config_new(mode, "tcp", "default"))
    assert(conf:set("rng", rng))
    assert(conf:set("dbg"))
    assert(conf:set("authmode", "none"))
    assert(conf:set("min_version", 1, 1))
    assert(conf:set("max_version", 1, 1))
    assert(conf:set("read_timeout", 1))

    local ca = assert(crt.new():parse(data.CNTLS_CA_CRT))
    local ss = assert(crt.new():parse(data.CNTLS_SS_CRT))
    local se = assert(crt.new():parse(data.CNTLS_SE_CRT))

    local pks = assert(pk.new():parse(data.CNTLS_SS_KEY, false, rng))
    local pke = assert(pk.new():parse(data.CNTLS_SE_KEY, false, rng))

    assert(conf:set("own_cert", ss, pks))
    assert(conf:set("own_cert", se, pke))
    return conf
end

describe("mbedtls tls tests", function()
    local srv_conf = create_ssl_conf("server")
    local cli_conf = create_ssl_conf("client")

    it("CNTLS tests", function()
        local srv = assert(ssl.ssl_new(srv_conf))
        local cli = assert(ssl.ssl_new(cli_conf))

        assert(srv:setup(srv_conf))
        assert(cli:setup(cli_conf))

        local to_srv, to_cli = {}, {}

        assert(srv:set("bio", cli, function(x, msg)
            to_cli[#to_cli + 1] = msg
            return #msg
        end, function(x, len)
            if #to_srv > 0 then
                local msg = table.remove(to_srv, 1)
                if #msg <= len then
                    return msg
                else
                    local last = msg:sub(len + 1, -1)
                    table.insert(to_srv, 1, last)
                    msg = msg:sub(1, len)
                    return msg
                end
            end
            return -0x6900
        end))

        assert(cli:set("bio", srv, function(x, msg)
            to_srv[#to_srv + 1] = msg
            return #msg
        end, function(x, len)
            if #to_cli > 0 then
                local msg = table.remove(to_cli, 1)
                if #msg <= len then
                    return msg
                else
                    local last = msg:sub(len + 1, -1)
                    table.insert(to_cli, 1, last)
                    msg = msg:sub(1, len)
                    return msg
                end
            end
            return -0x6900
        end))

        local bs, bc, ms, mc, cs, cc = true, true
        while bs and bc do
            bs, ms, cs = srv:handshake(true)
            bs = bs or ms:match("WANT") or ms:match("IN_PROCESS")
            bc, mc, cc = cli:handshake(true)
            bc = bc or mc:match("WANT") or mc:match("IN_PROCESS")
        end
        assert(cli:write(data.HTTP_REQUEST))

        assert(srv:read() == data.HTTP_REQUEST)
        assert(srv:write(data.HTTP_RESPONSE))

        assert(cli:read() == data.HTTP_RESPONSE)
    end)

    it("luv with CNTLS tests", function()
        local _, uv = pcall(require, "luv")
        if not _ then
            return
        end

        local host, port = "127.0.0.1", 9527

        local uvsrv = uv.new_tcp()
        local uvcli = uv.new_tcp()

        local to_srv, to_cli = {}, {}
        local srv = assert(ssl.ssl_new(srv_conf))
        local cli = assert(ssl.ssl_new(cli_conf))

        assert(srv:setup(srv_conf))
        assert(cli:setup(cli_conf))

        local handshake = {
            client = false,
            server = false
        }

        local function next_loop(handle, timeout)
            timeout = timeout or 0
            local timer = uv.new_timer()
            timer:start(timeout, 0, function()
                handle()
                timer:stop()
                timer:close()
            end)
        end

        local close = function(stream, err, mode)
            if err == "close" then
                srv:close_notify()
                cli:close_notify()
                return
            end

            ssl.eof = true
            if tostring(stream):match("tcp") then
                ssl:debug_print("verbose", string.format("%s CLOSE", stream))
                stream:read_stop()
                stream:close()

                return
            end

            if mode=='server' then
                uvsrv:read_stop()
                uvsrv:close(function()
                    uv.stop()
                end)
                return
            end
        end

        local is_error = function(ret, msg)
            if ret == nil then
                return true
            end

            if ret == false and not (msg:match("^WANT") or msg:match("^IN_PROCESS")) then
                return true
            end
            return false
        end
        local handle_ssl
        handle_ssl = function(ssl, mode)
            ssl:debug_print("verbose", string.format("*** %s %s", ssl, mode))
            if ssl:is_handshake_over() then
                if mode == "client" and not ssl.requested then
                    ssl:write(data.HTTP_REQUEST)
                    ssl:debug_print("verbose", string.format("client write"))
                    ssl.requested = true
                    return
                end

                local msg, err = ssl:read()
                if is_error(msg, err) then
                    return close(stream, err, mode)
                end

                if mode == "client" then
                    if msg == data.HTTP_RESPONSE then
                        ssl:debug_print("verbose", string.format("MSG: %s", msg))
                        return close(stream, "close", mode)
                    end
                else
                    if msg == data.HTTP_REQUEST then
                        local n = ssl:write(data.HTTP_RESPONSE)
                        assert(n==#data.HTTP_RESPONSE);
                    end
                end
            else
                local bs, ms, bc = ssl:handshake(true)
                if ms and ms:match("WANT") then
                    bs, ms, bc = ssl:handshake(true)
                end
                handshake[mode] = true
                if is_error(bs, ms) then
                    return close(stream, ms, mode)
                end
            end
        end

        local function handle_net(ssl, stream, queue, mode)

            -- 将来自网络的数据加密到 SSL 输入队列
            stream:read_start(function(err, data)
                if err then
                    return close(stream, err, mode)
                end

                if data == nil then
                    close(stream, "EOF", mode)
                    return
                end

                queue[#queue + 1] = data


                next_loop(function()
                    handle_ssl(ssl, mode)
                end)
            end)

            assert(ssl:set(
                "bio",
                stream,
                function(s, msg)
                    -- SSL 输出通信数据密文, 无需后续处理
                    ssl:debug_print("verbose", string.format(mode.."\t--SSL 输出通信数据密文"))
                    ssl:debug_print("verbose", string.format(">>>\t"..mbedtls.hex(msg)))
                    s:write(msg)
                    next_loop(function()
                        handle_ssl(ssl, mode)
                    end)
                    return #msg
                end,

                nil,

                function(x, len, timeout)
                    -- SSL 读取通讯数据密文, 激活 SSL 处理
                    ssl:debug_print("verbose", string.format(mode.."\t-- SSL 读取通讯数据密文"))
                    if #queue > 0 then
                        local msg = table.remove(queue, 1)
                        if #msg > len then
                            local last = msg:sub(len + 1, -1)
                            table.insert(queue, 1, last)
                            msg = msg:sub(1, len)
                        end
                        if #msg > 0 then
                            ssl:debug_print("verbose", string.format("<<<\t"..mbedtls.hex(msg)))
                            next_loop(function()
                                handle_ssl(ssl, mode)
                            end)
                            return msg
                        end
                    end

                    if mode=='server' and not cli:is_handshake_over() then
                        -- 强制发起客户端握手协商
                        next_loop(function()
                            handle_ssl(cli, "client")
                        end)
                    end
                    if ssl.eof then
                        return CONN_EOF
                    end
                    return WANT_READ
                end
            ))

            handle_ssl(ssl, mode)
            next_loop(function()
                handle_ssl(ssl, mode)
            end)
        end

        -- WARNING: 确保客户端先发起握手
        assert(uvsrv:bind(host, port))
        uvsrv:listen(128, function(err)
            -- Create socket handle for client
            local client = uv.new_tcp()

            -- Accept incoming connection
            uvsrv:accept(client)

            if handshake.client then
                handle_net(srv, client, to_srv, "server")
            else
                handle_net(cli, uvcli, to_cli, "client")
                next_loop(function()
                    handle_net(srv, client, to_srv, "server")
                end, 100)
            end
        end)

        uvcli:connect(host, port, function(err)
            if err then
                close(uvcli, err, mode)
            end

            handle_net(cli, uvcli, to_cli, "client")
        end)

        uv.run()
    end)
end)
----------------------------------------------------------------------
