local json = require "util.json";
local hashes = require "util.hashes";
local enc = require "util.encodings";

local function decode(b64str)
	local reminder = #b64str % 4;
	if reminder > 0 then
		b64str = b64str .. string.rep("=", 4 - reminder);
	end
	return enc.base64.decode(b64str);
end

local function encode(data)
	b64str = enc.base64.encode(data);
	return b64str:gsub("=", ""):gsub("+", "-"):gsub("/", "_"):gsub("=", "");
end

local function parse_jwt(token, secret)
	local header, payload, signature = string.match(token, "([^\.]+)\.([^\.]+)\.([^\.]+)");
	local base_string = header .. "." .. payload

	header = json.decode(decode(header))
	payload = json.decode(decode(payload))

	if not header then
		error("Invalid header")
	end
	if not payload then
		error("Invalid payload")
	end

	if header.typ ~= "JWT" then
		error("Unknow token type")
	end

	if header.alg == "HS256" then
		our_sig = encode(hashes.hmac_sha256(secret, base_string, false))
		their_sig = signature
		if our_sig ~= their_sig then
			error("Bad Signature")
		end
		return payload, header.alg
	end

	error("Unsupported Token type")
end

return {
	parse = parse_jwt;
}
