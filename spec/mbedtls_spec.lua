local mbedtls = require 'mbedtls'
local hex = mbedtls.hex

describe("mbedtls basic tests", function()

    describe("version", function()
        assert.are.equals("mbedtls", mbedtls._NAME)
        assert.are.equals("0.1.0", mbedtls._VERSION)

        local vers, vern = mbedtls.version()


        local _, _, major, minor, patch = vers:find("(%d+)%.(%d+)%.(%d+)")
        vers = tonumber(major)*0X1000000 + tonumber(minor)*0X10000 + tonumber(patch)*0X100

        assert.are.equals(vern, vers)

        assert.True(mbedtls.check_feature("MBEDTLS_AES_C"))
        assert.falsy(mbedtls.check_feature("MBEDTLS_XXXX_C"))
    end)

    describe("random", function()

        local data = assert(mbedtls.random(16))
        assert.are.equals(16, #data)
        data = assert(mbedtls.random(32))
        assert.are.equals(32, #data)
        data = assert(mbedtls.random(64))
        assert.are.equals(64, #data)
        data = assert(mbedtls.random(128))
        assert.are.equals(128, #data)

        data = assert(mbedtls.random())
        assert.has_error(function() return mbedtls.random(#data+1) end,
            "bad argument #1 to '?' (out of range [1, 1024])")

    end)

    describe("hex", function()

        assert.are.equals("31323334", hex('1234'))
        assert.are.equals("31323334", hex('1234', true))
        assert.are.equals("1234", hex('31323334', false))
        assert.are.equals("1234", hex('31323334', nil))
    end)

    describe("base64", function()
        local base64 = mbedtls.base64

        assert.are.equals('MTIzNA==', base64('1234'))
        assert.are.equals('MTIzNA==', base64('1234', true))
        assert.are.equals('1234', base64('MTIzNA==', false))
        assert.are.equals('1234', base64('MTIzNA==', nil))
    end)

    local msg = 'The quick brown fox jumps over the lazy dog'

    describe("hash", function()
        local md = mbedtls.md

        assert.are.equals('9e107d9d372bb6826bd81d3542a419d6',
            hex(md.hash('MD5', msg)))
    end)

    describe("hmac", function()
        local md = mbedtls.md

        assert.are.equals('80070713463e7749b90c2dc24911e275',
            hex(md.hmac('MD5', 'key', msg)))

        assert.are.equals('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9',
            hex(md.hmac('SHA1', 'key', msg)))

        assert.are.equals('f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
            hex(md.hmac('SHA256', 'key', msg)))
    end)
end)

