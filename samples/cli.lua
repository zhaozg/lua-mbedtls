local mbedtls = require'mbedtls'
local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng

local opts = {
    p = "443"
}
local nonoptions = {}
local getopt = require('getopt')

local function usage()
print([[
Usage:
    cli.lua -h hostname -p port -v -?

    -h: hostname to connect
    -p: port to connect
    -a: authmode none/require/optional [NYI]
    -c: ciphersites of ssl [NYI]
    -P: protocol ssl12/ssl13/cntls11 [NYI]
    -v: verbose output to debug
]])
end

for opt, arg in getopt(arg, 'h:p:P:v?', nonoptions) do
    if opt == 'h' then
        opts.h = arg
    elseif opt == 'p' then
        opts.p = arg
    elseif opt == 'P' then
        opts.P = arg
    elseif opt == '?' then
        usage()
        os.exit(0)
    elseif opt == 'v' then
        mbedtls.debug_set_threshold("verbose")
    elseif opt == ':' then
        print('error: missing argument: ' .. arg)
        os.exit(1)
    end
end

if (not (opts.h and opts.p)) then
    usage()
    os.exit(1)
    return
end

print(string.format('*** connect to %s:%s', opts.h, opts.p))

rng = assert(rng.new())

-- build ssl config
local conf = assert(ssl.config_new())

assert(conf:set('rng', rng))
assert(conf:set('dbg'))
assert(conf:set('authmode', 'none'))

if opts.P and opts.P:match('^cntls') then
    assert(conf:set('min_version', 1, 1))
    assert(conf:set('max_version', 1, 1))
    assert(conf:set("cntls"))
end

-- do network connect
local cli = assert(net.new())
assert(cli:connect(opts.h, opts.p))

-- do ssl connect
local scli = assert(ssl.ssl_new(conf))
assert(scli:setup(conf))
assert(scli:set('bio', cli))

assert(scli:handshake())

print(string.format('*** SSL handshake done'))
-- do ssl read/write

assert(scli:write('GET / HTTP/1.0\r\n\r\n'))

print(string.format('*** wait for response'))
print()

repeat
    local ret, err, code = scli:read()
    if ret then
        io.write(ret)
    elseif code ~= -30848 then
        print('ERROR:',code, err)
    end
until not ret
cli:close()

