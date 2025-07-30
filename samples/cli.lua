local mbedtls = require("mbedtls")
local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng
local pk = mbedtls.pk
local crt = mbedtls.crt

rng = assert(rng.new())

local uv

local opts = {
    p = "443",
    auth = 'mode',
    certs = {},
    keys = {},
}
local nonoptions = {}
local getopt = require("getopt")

local function usage()
    print([[
Usage:
    cli.lua -h hostname -p port -u -v -e -?

    -h: hostname to connect
    -p: port to connect
    -u: event mode with luv if support
    -a: authmode none/require/optional
    -c: ciphersites of ssl [NYI]
    -P: protocol tls12/tls13/cntls
    -v: verbose output to debug
    -e: echo mode
]])
end

local function loadfile(path)
    local f= assert(io.open(path, 'rb'))
    local ctx = f:read('*all')
    f:close()
    return ctx .. '\0'
end

for opt, arg in getopt(arg, "h:p:P:a:c:k:C:uve?", nonoptions) do
    if opt == "h" then
        opts.h = arg
    elseif opt == "p" then
        opts.p = arg
    elseif opt == "P" then
        opts.P = arg
    elseif opt == "u" then
        opts.uv, uv = pcall(require, "luv")
    elseif opt == "?" then
        usage()
        os.exit(0)
    elseif opt == 'e' then
        opts.e = true
    elseif opt == 'a' then
        opts.auth = arg
    elseif opt == 'C' then
        local cafile = loadfile(arg)
        opts.cacerts = assert(crt.new():parse(cafile), cafile)
    elseif opt == 'c' then
        local cert = loadfile(arg)
        opts.certs[#opts.certs+1] = assert(crt.new():parse(cert), arg)
    elseif opt == 'k' then
        local ctx = loadfile(arg)
        opts.keys[#opts.keys+1] = assert(pk.new():parse(ctx, false, rng), arg)
    elseif opt == "v" then
        if mbedtls.debug_set_threshold then
            mbedtls.debug_set_threshold("verbose")
        end
    elseif opt == ":" then
        print("error: missing argument: " .. arg)
        os.exit(1)
    end
end

if not (opts.h and opts.p) then
    usage()
    os.exit(1)
end

if opts.auth == 'required' and (#opts.certs ~= #opts.keys or #opts.certs == 0) then
    print("error: missing argument -c for certificates and -k for keys")
    usage()
    os.exit(1)
end

print(string.format("*** connect to %s:%s", opts.h, opts.p))

-- build ssl config
local conf = assert(ssl.config_new())

assert(conf:set("rng", rng))
assert(conf:set("dbg"))
assert(conf:set("authmode", opts.auth))

if opts.P and opts.P:match("^cntls") then
    assert(conf:set("min_tls_version", 1, 1))
    assert(conf:set("max_tls_version", 1, 1))
    assert(conf:set("cntls"))
end

if opts.cacerts then
    assert(conf:set('ca_chain', opts.cacerts))
end
for i=1, #opts.certs do
    assert(conf:set("own_cert", opts.certs[i], opts.keys[i]))
end
conf:set("verify", function(...)
    return 0
end)
local scli = assert(ssl.ssl_new(conf))
assert(scli:setup(conf))

-- with mbedtls
local function net_cli(scli)
    -- do network connect
    local cli = assert(net.new())
    assert(cli:connect(opts.h, opts.p))

    -- do ssl connect
    assert(scli:set("bio", cli))
    print(string.format("*** SSL handshaking..."))
    assert(scli:handshake())

    print(string.format("*** SSL handshake done"))
    -- do ssl read/write

    assert(scli:write("GET / HTTP/1.0\r\n\r\n"))

    print(string.format("*** wait for response"))
    print()

    repeat
        local ret, err, code = scli:read()
        if ret then
            io.write(ret)
        elseif code ~= -30848 then
            print("ERROR:", code, err)
        end
    until not ret
    cli:close()
end

-- with libuv
local function uv_cli(sslc)

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
            if (obj:is_handshake_over()) then
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
        stream:read_start(function(err, data)
            if err then
                return onData(stream, err, data)
            end

            if data then
                obj.queue[#obj.queue + 1] = data
            end

            delay_run(function()
                repeat
                    data, err, code = obj:read()
                    if data then
                        onData(stream, err, data, code)
                    elseif data == nil or not (err:match("^WANT") or err:match("^IN_PROCESS")) then
                        onData(stream, err, data, code)
                    end
                until not obj:check_pending()
            end)
        end)

        assert(obj:set(
            "bio",
            stream,
            function(s, msg)
                -- SSL 输出通信数据密文, 无需后续处理
                s:write(msg)
                return #msg
            end,

            function(_, len)
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
            end
        ))

        handshake(obj, onSecure)
    end

    local function onError(tcp, err, code)
        tcp:read_stop()
        tcp:close()
    end

    local uvcli = uv.new_tcp()

    uvcli:connect(opts.h, tonumber(opts.p), function(err)
        if err then
            onError(uvcli, err)
        end

        handle_ssl(scli, uvcli, function(err)
                print('onSecure and do REQUEST')
                if opts.e then
                    local msg = string.rep('x', 5*1024)
                    scli:write(msg)
                else
                    assert(scli:write("GET / HTTP/1.0\r\n\r\n"))
                end
            end,
            function(stream, err, data, code)
                if err then
                    onError(stream, err, code)
                    return
                end
                if opts.e then
                    scli:write(data)
                else
                    print('RESPONSE')
                    print(data)
                end
            end)
    end)
    uv.run()
end

if not uv then
    net_cli(scli)
else
    uv_cli(scli)
end

print("Done")
