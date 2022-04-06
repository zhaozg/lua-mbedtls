local mbedtls = require'mbedtls'
local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng

local pk = mbedtls.pk
local crt = mbedtls.crt
-----------------------------------------------------------------------------
local HTTP_RESPONSE =
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" ..
    "<h2>lua-mbedtls demo Server</h2>\r\n" ..
    "<p>Successful connection using: %s</p>\r\n"

local CNTLS_CA_CRT =
"-----BEGIN CERTIFICATE-----\r\n" ..
"MIIB7TCCAZSgAwIBAgIJAMQrlrJXxNk1MAoGCCqBHM9VAYN1MFIxCzAJBgNVBAYT\r\n" ..
"AkNOMRAwDgYDVQQHDAdIYWlEaWFuMQwwCgYDVQQKDANTQ0ExCzAJBgNVBAsMAlJE\r\n" ..
"MRYwFAYDVQQDDA1UZXN0IENBIChTTTIpMB4XDTIxMDQwOTA2MzUyMloXDTI1MDUx\r\n" ..
"ODA2MzUyMlowUjELMAkGA1UEBhMCQ04xEDAOBgNVBAcMB0hhaURpYW4xDDAKBgNV\r\n" ..
"BAoMA1NDQTELMAkGA1UECwwCUkQxFjAUBgNVBAMMDVRlc3QgQ0EgKFNNMikwWTAT\r\n" ..
"BgcqhkjOPQIBBggqgRzPVQGCLQNCAASN8UaIEh6W2MGzGDI3d5JZkoJ459jwS7jp\r\n" ..
"sowjr0NczxnggqO6kAxBZRx3OiU7j6L1PJU/S6MNHcL8XpZLIR3Mo1MwUTAdBgNV\r\n" ..
"HQ4EFgQUxPPXDcWy8lZGq6XBeKfy4SlRW6UwHwYDVR0jBBgwFoAUxPPXDcWy8lZG\r\n" ..
"q6XBeKfy4SlRW6UwDwYDVR0TAQH/BAUwAwEB/zAKBggqgRzPVQGDdQNHADBEAiBN\r\n" ..
"sG3oGEs7Jnwtbm+ARC8HHsNDGTdFWDai8+ihjB50sQIgO5gx4lDVE/9OsEFVSPkR\r\n" ..
"km2a9A0Q7cQ9rEwRRJxvdTo=\r\n" ..
"-----END CERTIFICATE-----\0"

local CNTLS_SS_CRT =
"-----BEGIN CERTIFICATE-----\r\n" ..
"MIIBuDCCAV+gAwIBAgIJAOhbkNuGJ2sRMAoGCCqBHM9VAYN1MFIxCzAJBgNVBAYT\r\n" ..
"AkNOMRAwDgYDVQQHDAdIYWlEaWFuMQwwCgYDVQQKDANTQ0ExCzAJBgNVBAsMAlJE\r\n" ..
"MRYwFAYDVQQDDA1UZXN0IENBIChTTTIpMB4XDTIxMDQwOTA2MzUyMloXDTI1MDUx\r\n" ..
"ODA2MzUyMlowVjELMAkGA1UEBhMCQ04xEDAOBgNVBAcMB0hhaURpYW4xDDAKBgNV\r\n" ..
"BAoMA1NDQTELMAkGA1UECwwCUkQxGjAYBgNVBAMMEXNlcnZlciBzaWduIChTTTIp\r\n" ..
"MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEdVKq9V2xVLK/J1qQ5VraKy2SUMLQ\r\n" ..
"mRbum8o7pkjD1l4lKJi6ySYCj8MeFBNrMMaei7eDPAIFZbh70dy3WYnlB6MaMBgw\r\n" ..
"CQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwCgYIKoEcz1UBg3UDRwAwRAIgZC7FQJgs\r\n" ..
"HlWXc1+FajUuP7m6cChD38WJiODS7EfXuAQCIGxAI+8c2d7hTyqoikUUrGju0JqU\r\n" ..
"+9YsuW+gNA42T4WR\r\n" ..
"-----END CERTIFICATE-----\0"

local CNTLS_SS_KEY =
"-----BEGIN PRIVATE KEY-----\r\n" ..
"MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgHTTFaKoxe4w9psWM\r\n" ..
"20uyjNXIdisZvbT9Rz22TP0Z5M+hRANCAAR1Uqr1XbFUsr8nWpDlWtorLZJQwtCZ\r\n" ..
"Fu6byjumSMPWXiUomLrJJgKPwx4UE2swxp6Lt4M8AgVluHvR3LdZieUH\r\n" ..
"-----END PRIVATE KEY-----\0"

local CNTLS_SE_CRT =
"-----BEGIN CERTIFICATE-----\r\n" ..
"MIIBtzCCAV6gAwIBAgIJAOhbkNuGJ2sSMAoGCCqBHM9VAYN1MFIxCzAJBgNVBAYT\r\n" ..
"AkNOMRAwDgYDVQQHDAdIYWlEaWFuMQwwCgYDVQQKDANTQ0ExCzAJBgNVBAsMAlJE\r\n" ..
"MRYwFAYDVQQDDA1UZXN0IENBIChTTTIpMB4XDTIxMDQwOTA2MzUyMloXDTI1MDUx\r\n" ..
"ODA2MzUyMlowVTELMAkGA1UEBhMCQ04xEDAOBgNVBAcMB0hhaURpYW4xDDAKBgNV\r\n" ..
"BAoMA1NDQTELMAkGA1UECwwCUkQxGTAXBgNVBAMMEHNlcnZlciBlbmMgKFNNMikw\r\n" ..
"WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQy2zVirh1xDpI/J6euRiWTJBIvVMrF\r\n" ..
"F09E11J9mQekVnng++fXiUrlOJpD2qLQPPCjZqURhAJvu4JhUjf7O09joxowGDAJ\r\n" ..
"BgNVHRMEAjAAMAsGA1UdDwQEAwIDODAKBggqgRzPVQGDdQNHADBEAiB1T/HxIsPw\r\n" ..
"kzBV6LMjo1Fd2SBFHOjrTBFDuQ6Y7HnrBQIgJxauVxqerMSjyAze8mz3JmmT/XGT\r\n" ..
"eq8M8Mx69c+4mwA=\r\n" ..
"-----END CERTIFICATE-----\0"

local CNTLS_SE_KEY =
"-----BEGIN PRIVATE KEY-----\r\n" ..
"MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgn0b9p4xD6F0b4z9C\r\n" ..
"qjU8xOpVTjWcdGpwEngrRmzO7IehRANCAAQy2zVirh1xDpI/J6euRiWTJBIvVMrF\r\n" ..
"F09E11J9mQekVnng++fXiUrlOJpD2qLQPPCjZqURhAJvu4JhUjf7O09j\r\n" ..
"-----END PRIVATE KEY-----\0"


----------------------------------------------------------------------
local nonoptions = {}
local getopt = require('getopt')

local opts = {
    h = '0.0.0.0',
    p = '4443'
}

local function usage()
print(string.format[[
Usage:
    %s -h hostname -p port -v -?

    -h: hostname to bind
    -p: port to bind
    -a: authmode none/require/optional [NYI]
    -c: ciphersites of ssl [NYI]
    -P: protocol ssl12/ssl13/cntls11 [NYI]
    -v: verbose output to debug
]], arg[0])
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
assert(opts.h and opts.p, "missing bind hostname or port")

local function create_ssl_conf(rng, protocol)
    local conf = assert(ssl.config_new('server', 'tcp', 'default'))
    assert(conf:set('rng', rng))
    assert(conf:set('dbg'))
    assert(conf:set('authmode', 'none'))

    print("protocol and protocol:match('^cntls')", protocol and protocol:match('^cntls'))
    if protocol and protocol:match('^cntls') then
        assert(conf:set('min_version', 1, 1))
        assert(conf:set('max_version', 1, 1))
        assert(conf:set('cntls'))
    end

    local ca = assert(crt.new():parse(CNTLS_CA_CRT))
    local ss = assert(crt.new():parse(CNTLS_SS_CRT))
    local se = assert(crt.new():parse(CNTLS_SE_CRT))

    local pks = assert(pk.new():parse(CNTLS_SS_KEY, false, rng))
    local pke = assert(pk.new():parse(CNTLS_SE_KEY, false, rng))

    assert(conf:set('own_cert', ss, pks))
    assert(conf:set('own_cert', se, pke))
    return conf
end

rng = assert(rng.new())

-- build ssl config
local conf = create_ssl_conf(rng, opts.P)


-- make listen port
local bio = assert(net.new())
assert(bio:bind(opts.h, opts.p))

while true do

    local cli, ip = assert(bio:accept())
    print("*** accept connect from ".. ip)

    --- make a ssl client connection
    local ssl = assert(ssl.ssl_new(conf))
    assert(ssl:setup(conf))
    assert(ssl:set('bio', cli))

    -- do handshake
    assert(ssl:handshake())
    print("*** handshake done")

    local req, resp, err = ""
    repeat
        req = req .. assert(ssl:read())
    until req==nil or req:match("\r\n\r\n")
    if req then
        resp = string.format(HTTP_RESPONSE, tostring(ssl))
        local n = 0, i, err
        repeat
            n = n + assert(ssl:write(resp:sub(n+1, -1)))
        until n==#resp
    end
    assert(ssl:close_notify())
    cli:close()
    print("*** connection closed")
end


