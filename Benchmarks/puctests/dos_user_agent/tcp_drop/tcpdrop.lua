local unpack = require'unpack'
local eth_p_ip = 0x0800
local ipproto_tcp = 6

local function parsemac(packet)
	local maclen = 14
	return unpack.int(packet, 12, 16), maclen
end

local function parseip(packet, ipoff)
	return unpack.int(packet, ipoff + 9, 8), unpack.int(packet, ipoff, 4)
end

local function parsetcp(packet, tcpoff)
	return unpack.int(packet, tcpoff + 2, 16)
end

function tcpchecker(packet)
	local mactype, maclen = parsemac(packet)
	if mactype ~= eth_p_ip then
		return false
	end

	local ipproto, iplen = parseip(packet, maclen)
	if ipproto ~= ipproto_tcp then
		return false
	end

	local dport = parsetcp(packet, maclen + iplen * 4)
	if dport == 80 then
		return true
	end
	return false
end
