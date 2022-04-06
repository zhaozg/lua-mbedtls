local mbedtls = require'mbedtls'
local ssl = mbedtls.ssl
local net = mbedtls.net
local rng = mbedtls.rng

local pk  = mbedtls.pk
local crt = mbedtls.crt

mbedtls.debug_set_threshold("error")

rng = assert(rng.new())
-----------------------------------------------------------------------------
local HTTP_RESPONSE =
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" ..
    "<h2>mbed TLS Test Server</h2>\r\n" ..
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


local function create_ssl_conf(mode)
    assert(mode=='server' or mode=='client')
    local conf = assert(ssl.config_new(mode, 'tcp', 'default'))
    print('set rng', conf:set('rng', rng))
    print('set dbg', conf:set('dbg'))
    print('set authmode', conf:set('authmode', 'none'))
    print('set authmode', conf:set('min_version', 1, 1))
    print('set authmode', conf:set('max_version', 1, 1))

    local ca = assert(crt.new():parse(CNTLS_CA_CRT))
    local ss = assert(crt.new():parse(CNTLS_SS_CRT))
    local se = assert(crt.new():parse(CNTLS_SE_CRT))

    local pks = assert(pk.new():parse(CNTLS_SS_KEY, false, rng))
    local pke = assert(pk.new():parse(CNTLS_SE_KEY, false, rng))

    assert(conf:set('own_cert', ss, pks))
    assert(conf:set('own_cert', se, pke))
    return conf
end

----------------------------------------------------------------------

local srv_conf = create_ssl_conf('server')
local cli_conf = create_ssl_conf('client')

local srv = assert(ssl.ssl_new(srv_conf))
local cli = assert(ssl.ssl_new(cli_conf))


assert(srv:setup(srv_conf))
assert(cli:setup(cli_conf))

local to_srv, to_cli = {}, {}

assert(srv:set('bio', cli,
function(x, msg)
    to_cli[#to_cli+1] = msg
    return #msg
end,
function(x, len)
    if #to_srv > 0 then
        local msg = table.remove(to_srv, 1)
        if #msg <= len then
            return msg
        else
            local last = msg:sub(len+1, -1)
            table.insert(to_srv, 1, last)
            msg = msg:sub(1, len)
            return msg
        end
    end
    return -0x6900
end
--,function(x, len, timeout)
--end
))

assert(cli:set('bio', srv,
function(x, msg)
    to_srv[#to_srv+1] = msg
    return #msg
end,
function(x, len)
    if #to_cli > 0 then
        local msg = table.remove(to_cli, 1)
        if #msg <= len then
            return msg
        else
            local last = msg:sub(len+1, -1)
            table.insert(to_cli, 1, last)
            msg = msg:sub(1, len)
            return msg
        end
    end
    return -0x6900
end
--,function(x, len, timeout)
--end
))
local bs, bc, ms, mc, cs, cc = true, true
while bs and bc do
    bs, ms, cs = srv:handshake(true)
    bs = bs or ms:match('WANT') or ms:match("IN_PROCESS")
    bc, mc, cc = cli:handshake(true)
    bc = bc or mc:match('WANT') or mc:match("IN_PROCESS")
end
local req = 'GET / HTTP/1.0\r\n\r\n'
assert(cli:write(req))
assert(srv:read()==req)
assert(srv:write(HTTP_RESPONSE))

assert(cli:read()==HTTP_RESPONSE)
print('DONE')

