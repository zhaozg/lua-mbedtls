local mbedtls = require("mbedtls")
local hex = mbedtls.hex

describe("mbedtls crypto tests", function()
    local msg = "The quick brown fox jumps over the lazy dog"

    describe("digest tests", function()
        local md = mbedtls.md

        local algs = md.list()
        assert.True(#algs > 0)

        describe("hash tests", function()
            for i = 1, #algs do
                it(algs[i], function()
                    local obj = md.new(algs[i])
                    obj:update(msg:sub(1, 1))
                    obj:update(msg:sub(2))
                    local ret = obj:finish()
                    assert.are.equals(obj:size(), #ret)

                    assert.are.equals(algs[i], obj:name())
                    if algs[i] == "SHA256" then
                        assert.are.equals(
                            "d7a8fbb307d7809469ca9abcb0082e4f" ..
                            "8d5651e46d3cdb762d02d0bf37c9e592",
                            hex(ret)
                        )
                    end
                end)
            end
        end)

        describe("hmac tests", function()
            for i = 1, #algs do
                it(algs[i], function()
                    local obj = md.new(algs[i], "key")
                    obj:update(msg:sub(1, 1))
                    obj:update(msg:sub(2))
                    local ret = obj:finish()
                    assert.are.equals(obj:size(), #ret)

                    assert.are.equals(algs[i], obj:name())
                    if algs[i] == "SHA256" then
                        assert.are.equals(
                            "f7bc83f430538424b13298e6aa6fb143" ..
                            "ef4d59a14946175997479dbc2d1a3cd8",
                            hex(ret)
                        )
                    end
                end)
            end
        end)
    end)

    describe("cipher tests", function()
        local cipher = mbedtls.cipher

        local algs = cipher.list()
        assert.True(#algs > 0)

        for i = 1, #algs do
            if
                (algs[i]:match("AES") or algs[i]:match("SM4"))
                and (algs[i]:match("-CBC$") or algs[i]:match("-ECB$"))
            then
                it(algs[i], function()
                    local obj = cipher.new(algs[i])
                    local kl, bl = assert(obj:get("keylen")), assert(obj:get("blocksize"))
                    local key = mbedtls.random(kl)
                    local iv = mbedtls.random(bl)
                    local dat = mbedtls.random(2 * bl)

                    local ret, raw = "", ""

                    -- encrypt
                    assert(obj:set("key", key, true))
                    --assert(obj:set('pad', 'PKCS7'))
                    if not algs[i]:match("-ECB$") then
                        assert(obj:set("iv", iv))
                    end

                    ret = ret .. assert(obj:update(dat:sub(1, bl)))
                    ret = ret .. assert(obj:update(dat:sub(bl + 1)))
                    ret = ret .. assert(obj:finish())

                    obj:reset()

                    -- decrypt
                    assert(obj:set("key", key, false))
                    --assert(obj:set('pad', 'PKCS7'))
                    if not algs[i]:match("-ECB$") then
                        assert(obj:set("iv", iv))
                    end

                    raw = raw .. assert(obj:update(ret:sub(1, bl)))
                    raw = raw .. assert(obj:update(ret:sub(bl + 1)))
                    raw = raw .. assert(obj:finish())

                    assert(#dat == #raw)
                    assert(dat == raw)
                end)
            end
        end
    end)

    describe("SM2 tests", function()
        local pk = mbedtls.pk
        local rng = mbedtls.rng
        local drbg = rng.new()

        local kp = assert(pk.new("ECKEY"))
        assert(kp:genkey(drbg, "sm2p256v1"))
        assert(kp:cando('ECKEY'))

        local data, pub

        data = assert(kp:write(true, false))
        pub = assert(pk.new())
        assert(pub:parse(data .. '\0', true))

        -- data = assert(kp:write(true, true))
        -- print(mbedtls.hex(data))
        -- pub = assert(pk.new())
        -- assert(pub:parse(data, true))

        local items = {"type", "name", "len", "bitlen"}
        for i=1, #items do
            assert(kp:get(items[i]))
        end


        local hash = "01234566789012345667890123456678901234566789"
        local sig = assert(kp:sign(hash, "SM3", drbg))
        assert(pub:verify(hash, "SM3", sig))

        local cipher = assert(pub:encrypt(hash, drbg))
        local msg = assert(kp:decrypt(cipher, drbg))
        assert(msg==hash)
    end)

end)
