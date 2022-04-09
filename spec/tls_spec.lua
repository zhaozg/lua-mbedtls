local mbedtls = require("mbedtls")
package.path = "spec/?.lua;" .. package.path

local data = require("data")

local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng

local pk = mbedtls.pk
local crt = mbedtls.crt

rng = assert(rng.new())

local WANT_READ, WANT_WRITE = ssl.WANT_READ, ssl.WANT_WRITE
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

    --[[
    it("luv with CNTLS tests", function()
        local _, uv = pcall(require, 'luv')
        if not _ then return end

        for k, v in pairs(ssl) do
            print(k, v)
        end

        local host, port = '127.0.0.1', 9527

        local uvsrv = uv.new_tcp()
        local uvcli = uv.new_tcp()

        local to_srv, to_cli = {}, {}
        local srv = assert(ssl.ssl_new(srv_conf))
        local cli = assert(ssl.ssl_new(cli_conf))

        assert(srv:setup(srv_conf))
        assert(cli:setup(cli_conf))

        local close = function(cli, err)
            print('*****8ERROR', cli, err)
            cli:read_stop()
            cli:close()
            uvsrv:read_stop()
            uvsrv:close()

            local timer = uv.new_timer()
            timer:start(500, 0, function ()
                timer:stop()
                timer:close(function()
                    uv.stop()
                end)
            end)
        end

        local is_error = function(ret, msg)
            print(ret, msg)
            if ret==nil then
                return true
            end
            if ret==false and not (msg:match("^WANT") or msg:match("^IN_PROCESS")) then
                return true
            end
            return false
        end

        local function handle_cli(ssl, stream, queue, mode)
            print('MODE:', mode)

            -- 将来自网络的数据加密到 SSL 输入队列
            stream:read_start(function(err, data)
              if err then close(stream, err) return end
              if #data==0 then close("EOF") return end

              queue[#queue + 1] = queue
            end)

            assert(ssl:set('bio', stream, function(s, msg)
                -- SSL 输出通信数据密文
                print(mode, "--SSL 输出通信数据密文")
                print('>>>', mbedtls.hex(msg))
                s:write(msg)
                return #msg
            end,

            nil,
            function(x, len, timeout)
                -- SSL 读取通讯数据密文
                print(mode, '-- SSL 读取通讯数据密文')
                if #queue > 0 then
                    local msg = table.remove(queue, 1)
                    if #msg > len then
                        local last = msg:sub(len+1, -1)
                        table.insert(queue, 1, last)
                        msg = msg:sub(1, len)
                    end
                    if #msg > 0 then
                        return msg
                    end
                end
                return WANT_READ
            end))

            local check = uv.new_prepare()

            check:start(function()
              print('check', check, ssl:check_pending())
              if ssl:check_pending() then
                  return
              end

              if ssl:is_handshake_over() then
                local msg, err = ssl:read()
                if is_error(msg, err) then
                    return close(stream, err)
                end
                print(mode, 'data到了', ssl, msg, err)
              else
                local bs, ms, bc = ssl:handshake(true)
                print(mode, 'HANDSHAKE', bs, ms, bc, ssl:is_handshake_over())
                if is_error(bs, ms) then
                    return close(stream, ms)
                end
                local bs, ms, bc = ssl:handshake(true)
              end
            end)
        end

        assert(uvsrv:bind(host, port))
        uvsrv:listen(128, function(err)
            -- Create socket handle for client
            local client = uv.new_tcp()

            -- Accept incoming connection
            uvsrv:accept(client)

            local timer = uv.new_timer()
            timer:start(60, 0, function ()
                handle_cli(srv, client, to_srv, 'server')
            end)
        end)

        local timer = uv.new_timer()
        timer:start(50, 0, function ()
            uvcli:connect(host, port, function(err)
              if err then close(uvcli, err) end

              handle_cli(cli, uvcli, to_cli, 'client')
            end)
            timer:stop()
            timer:close()
        end)
        uv.run()
    end)
--]]
end)
----------------------------------------------------------------------
