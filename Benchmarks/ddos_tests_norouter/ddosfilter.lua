local eth_p_ip = 0x0800
local ipproto_tcp = 6

local xdpaction = {
	abort		= 0,
	drop		= 1,
	pass		= 2,
	tx		= 3,
	redirect 	= 4,
}

local function parsemac(packet)
	local maclen = 14
	return unpack.unpackint(packet, 12, 16), maclen
end

local function parseip(packet, ipoff)
	return unpack.unpackint(packet, ipoff + 9, 8), unpack.unpackint(packet, ipoff, 4)
end

local function parsetcp(packet, tcpoff)
	return unpack.unpackint(packet, tcpoff + 2, 16)
end

function callback(packet)
	local mactype, maclen = parsemac(packet)
	if mactype ~= eth_p_ip then
		return xdpaction.pass
	end

	local ipproto, iplen = parseip(packet, maclen)
	if ipproto ~= ipproto_tcp then
		return xdpaction.pass
	end

	local dport = parsetcp(packet, maclen + iplen * 4)
	if dport == 80 then
		return xdpaction.drop
	end
	return xdpaction.pass
end
