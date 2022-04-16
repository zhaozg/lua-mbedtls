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

        local function delay_run(handle, timeout)
            timeout = timeout or 0
            local timer = uv.new_timer()
            timer:start(timeout, 0, function()
                handle()
                timer:stop()
                timer:close()
            end)
        end

        local function handshake(obj, onSecure)
            local check = uv.new_check()
            check:start(function()
                obj:handshake()
                if obj:is_handshake_over() then
                    check:stop()
                    check:close()
                    onSecure()
                    obj.check = nil
                end
            end)
            obj.check = check
        end

        local function handle_ssl(obj, stream, onSecure, onData)
            obj.queue = {}
            local code

            -- 将来自网络的数据加密到 SSL 输入队列
            stream:read_start(function(err, msg)
                if err then
                    return onData(stream, err, msg)
                end

                if msg then
                    obj.queue[#obj.queue + 1] = msg
                end

                delay_run(function()
                    repeat
                        msg, err, code = obj:read()
                        if msg then
                            onData(stream, err, msg, code)
                        elseif msg == nil or not (err:match("^WANT") or err:match("^IN_PROCESS")) then
                            onData(stream, err, msg, code)
                        end
                    until not obj:check_pending()
                end)
            end)

            assert(obj:set("bio", stream, function(s, msg)
                -- SSL 输出通信数据密文, 无需后续处理
                s:write(msg)
                return #msg
            end, function(_, len)
                -- SSL 读取通讯数据密文, 激活 SSL 处理
                if #obj.queue > 0 then
                    local queue = obj.queue
                    local msg = table.remove(queue, 1)
                    if #msg > len then
                        local last = msg:sub(len + 1, -1)
                        table.insert(queue, 1, last)
                        msg = msg:sub(1, len)
                    end

                    if #queue > 0 then
                        delay_run(function()
                            obj:check_pending()
                        end)
                    end

                    if #msg > 0 then
                        return msg
                    end
                end

                if obj.eof then
                    onData(stream, "EOF", nil, ssl.CONF_EOF)
                    return ssl.CONN_EOF
                end
                return ssl.WANT_READ
            end))

            handshake(obj, onSecure)
        end

        local host, port = "127.0.0.1", 9527

        local uvsrv = uv.new_tcp()
        local uvcli = uv.new_tcp()

        local srv = assert(ssl.ssl_new(srv_conf))
        local cli = assert(ssl.ssl_new(cli_conf))

        assert(srv:setup(srv_conf))
        assert(cli:setup(cli_conf))

        local function onError(tcp, err, code)
            tcp:read_stop()
            tcp:close()
            if not uvsrv:is_closing() then
                uvsrv:close()
            end
        end

        assert(uvsrv:bind(host, port))
        uvsrv:listen(128, function(err)
            assert(not errx, err)
            -- Create socket handle for client
            local uvcli = uv.new_tcp()

            -- Accept incoming connection
            uvsrv:accept(uvcli)

            srv.request = ""
            handle_ssl(srv, uvcli, function()
                -- do some check
            end, function(stream, err, msg, code)
                if err then
                    onError(stream, err, code)
                    return
                end
                srv.request = srv.request .. msg
                if srv.request:match("\r\n\r\n") then
                    srv:write(data.HTTP_RESPONSE)
                    srv:close_notify()
                    delay_run(function()
                        onError(stream)
                    end)
                end
            end)
        end)

        uvcli:connect(host, port, function(err)
            if err then
                onError(uvcli, err)
            end

            handle_ssl(cli, uvcli, function(err)
                assert(cli:write(data.HTTP_REQUEST))
            end, function(stream, err, msg, code)
                if err then
                    onError(stream, err, code)
                    return
                end
                assert.are.equals(data.HTTP_RESPONSE, msg)
            end)
        end)

        uv.run()
    end)
end)
----------------------------------------------------------------------
