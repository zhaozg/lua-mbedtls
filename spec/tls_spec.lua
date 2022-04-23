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
    assert(conf:set("min_tls_version", 0x0101))
    assert(conf:set("max_tls_version", 0x0101))

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
        local srv = assert(ssl.ssl_new())
        local cli = assert(ssl.ssl_new())

        assert(srv:setup(srv_conf))
        assert(cli:setup(cli_conf))

        local to_srv, to_cli = {}, {}

        assert(srv:set("bio", cli, function(x, msg)
            to_cli[#to_cli + 1] = msg
            return #msg
        end, function(x, len)
            if #to_srv > 0 then
                local msg = table.concat(to_srv)
                if #msg > len then
                    local last = msg:sub(len + 1, -1)
                    to_srv = {last}
                    msg = msg:sub(1, len)
                else
                    to_srv = {}
                end

                return msg
            end
            return WANT_READ
        end))

        assert(cli:set("bio", srv, function(x, msg)
            to_srv[#to_srv + 1] = msg
            return #msg
        end, function(x, len)
            if #to_cli > 0 then
                local msg = table.concat(to_cli)
                if #msg > len then
                    local last = msg:sub(len + 1, -1)
                    to_cli = {last}
                    msg = msg:sub(1, len)
                else
                    to_cli = {}
                end

                return msg
            end
            return WANT_READ
        end))

        local bs, bc, ms, mc, cs, cc
        bs, bc = true, true

        while not (srv:is_handshake_over() and cli:is_handshake_over()) do
            bs, ms, cs = srv:handshake(true)
            bs = bs or ms:match("WANT") or ms:match("IN_PROCESS")
            bc, mc, cc = cli:handshake(true)
            bc = bc or mc:match("WANT") or mc:match("IN_PROCESS")
            assert(cs==nil)
            assert(cc==nil)
        end
        assert(srv:is_handshake_over() and cli:is_handshake_over())
        assert(cli:write(data.HTTP_REQUEST))

        assert(srv:read() == data.HTTP_REQUEST)
        assert(srv:write(data.HTTP_RESPONSE))

        assert(cli:read() == data.HTTP_RESPONSE)
        cli:close_notify()
        srv:close_notify()
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
            local check = uv.new_idle()
            check:start(function()
                obj:handshake(true)
                if obj:is_handshake_over() then
                    check:stop()
                    check:close()
                    --onSecure must be called delay, or crash
                    delay_run(onSecure)
                    obj.connected = true
                end
            end)
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

                if not obj.connected then
                    return
                end

                delay_run(function()
                    repeat
                        msg, err, code = obj:read()
                        if msg then
                            onData(stream, err, msg, code)
                        elseif msg == nil or not (err:match("^WANT") or err:match("^IN_PROCESS")) then
                            onData(stream, err, msg, code)
                        end
                    until not msg
                end)
            end)

            assert(obj:set("bio", stream, function(s, msg)
                -- SSL 输出通信数据密文, 无需后续处理
                s:write(msg)
                return #msg
            end, function(_, len)
                -- SSL 读取通讯数据密文, 激活 SSL 处理
                if #obj.queue > 0 then
                    local msg = table.concat(obj.queue)
                    if #msg > len then
                        local last = msg:sub(len + 1, -1)
                        obj.queue = {last}
                        msg = msg:sub(1, len)
                    else
                        obj.queue = {}
                    end

                    if #msg > 0 then
                        return msg
                    end
                end

                return WANT_READ
            end))
            handshake(obj, onSecure)
        end

        local host, port = "127.0.0.1", 9527

        local uvsrv = uv.new_tcp()
        local function onError(tcp, err, code)
            tcp:read_stop()
            tcp:close()
            if not uvsrv:is_closing() then
                uvsrv:close()
            end
            assert(err=='CLOSE_NOTIFY')
        end

        assert(uvsrv:bind(host, port))
        uvsrv:listen(128, function(err)
            assert(not err, err)
            -- Create socket handle for client
            local clix = uv.new_tcp()

            -- Accept incoming connection
            uvsrv:accept(clix)

            local srv = assert(ssl.ssl_new())
            assert(srv:setup(srv_conf))
            srv.request = ""

            handle_ssl(srv, clix, function()
                assert(srv.connected, clix)
                -- do some check
            end, function(stream, errx, msg, code)
                if errx then
                    onError(stream, errx, code)
                    return
                end
                srv.request = srv.request .. msg
                if srv.request:match("\r\n\r\n") then
                    assert(srv:write(data.HTTP_RESPONSE))
                    srv:close_notify()
                end
            end)
        end)

        local uvcli = uv.new_tcp()

        uvcli:connect(host, port, function(err)
            if err then
                onError(uvcli, err)
            end

            local cli = assert(ssl.ssl_new())
            assert(cli:setup(cli_conf))

            handle_ssl(cli, uvcli, function()
                assert(cli.connected, uvcli)
                assert(cli:write(data.HTTP_REQUEST))
            end, function(stream, errx, msg, code)
                if errx then
                    onError(stream, errx, code)
                    return
                end
                assert.are.equals(data.HTTP_RESPONSE, msg)
                cli:close_notify()
            end)
        end)

        uv.run()
    end)
end)
----------------------------------------------------------------------
