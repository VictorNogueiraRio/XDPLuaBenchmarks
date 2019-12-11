local data = require'data'
local xdplua = require'xdplua'

local blacklist = {
	['curl/7.54.0'] = true,
}

function checkuseragent(pkt)
	return blacklist[string.match(pkt, "User%-Agent:%s(.-)\r\n")]
end
