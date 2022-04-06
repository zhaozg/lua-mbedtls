local mbedtls = require 'mbedtls'
print(require'inspect'(mbedtls))

local base64 = require 'mbedtls'.base64
local hex = require 'mbedtls'.hex
local md = require 'mbedtls'.md
local ssl = require 'mbedtls'.ssl

assert(base64('1234') == 'MTIzNA==')
assert(base64('1234', true) == 'MTIzNA==')
assert(base64('MTIzNA==', false) == '1234')
assert(base64('MTIzNA==', nil) == '1234')

assert(md.hash('MD5', 'The quick brown fox jumps over the lazy dog') == hex('9e107d9d372bb6826bd81d3542a419d6', false))
assert(md.hmac('MD5', 'key', 'The quick brown fox jumps over the lazy dog') == hex('80070713463e7749b90c2dc24911e275', false))
assert(md.hmac('SHA1', 'key', 'The quick brown fox jumps over the lazy dog') == hex('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9', false))
assert(md.hmac('SHA256', 'key', 'The quick brown fox jumps over the lazy dog') == hex('f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8', false))

