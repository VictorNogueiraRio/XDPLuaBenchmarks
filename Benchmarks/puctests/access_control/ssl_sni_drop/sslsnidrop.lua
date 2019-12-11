local data = require'data'
xdplua = require'xdplua'
local unpack = require'unpack'

local xdpaction = {
	abort		= 0,
	drop		= 1,
	pass		= 2,
	tx		= 3,
	rediretct	= 4,
}

local blacklist = {
	['test.com'] = true,
	['test2.com.br'] = true,
}

local function extractsni(pkt)
	local clienthello = 0x01
	local handshake = 0x16
	local servername = 0
	local randlen, handshakelen, compressionlen = 32, 10, 4
	local contenttype = unpack.int(pkt, 0, 8 * 1)	
	local handshaketype = unpack.int(pkt, 5, 8 * 1)
	if contenttype ~= handshake or
		handshaketype ~= clienthello then
		return
	end

	local sslsessionoff = handshakelen + randlen + 1

	local sslsessionlen = unpack.int(pkt, sslsessionoff, 1 * 8)
	local sslcipheroff = sslsessionoff + sslsessionlen + 1

	local sslcipherlen = unpack.int(pkt, sslcipheroff, 2 * 8)
	local sslcompressionoff = sslcipheroff + sslcipherlen + 2

	local exttotlen = unpack.int(pkt, sslcompressionoff + 2, 2 *8)
	local extbytes = 0
	local extoff = sslcompressionoff + 4
	local exttype = unpack.int(pkt, extoff, 2 * 8)
	while exttotlen >= extbytes do
		local exttype = unpack.int(pkt, extoff, 2 * 8)
		local extlen = unpack.int(pkt, extoff + 2, 2 * 8)
		if exttype == servername then
			local snioff = extoff + 4
			local snilen = unpack.int(pkt, snioff + 3, 2 * 8)
			local sni = unpack.string(pkt, snioff + 5, snilen)
			return sni
		end

		extbytes = extbytes + extlen
		extoff = extoff + extlen + 4
	end
end

function checksni(pkt)
	return blacklist[extractsni(pkt)]
end
