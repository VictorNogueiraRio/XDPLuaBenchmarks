eth_p_ip = 0x0800
ipproto_tcp = 6

local function parsemac(packet)
	local maclen = 14
	local layout = data.layout{dst = {0, 6*8}, src = {6*8, 6*8}, type = {12*8, 2*8}}
	local macdata = packet:layout(layout)
	return macdata.type, maclen
end

function parseip(packet)
	local layout = data.layout{ihl = {4, 4}, proto = {72, 8}}
	local ipdata = packet:layout(layout)
	return ipdata.proto, ipdata.ihl * 4
end

function parsetcp(packet)
	local layout = data.layout{source = {0, 2*8, 'net'}, destination = {2*8, 2*8, 'net'}}
	local tcpdata = packet:layout(layout)
	return tcpdata.source
end

function callback(packet)
	local mactype, maclen = parsemac(packet)
	if mactype ~= eth_p_ip then
		return 2
	end

	packet = packet:segment(maclen)
	local ipproto, iplen = parseip(packet)
	if ipproto ~= 6 then
		return 2
	end

	packet = packet:segment(iplen)
	local sport = parsetcp(packet)
	if sport == 1234 then
		return 1
	end
	return 2
end
