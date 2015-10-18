local usermanager = require "core.usermanager";
local new_sasl = require "util.sasl".new;

local log = module._log;
local host = module.host;

local accounts = module:open_store("accounts");
local signing_secret = module:get_option_string("jwt_signing_secret");
local jwt = module:require "jwt";

-- define auth provider
local provider = {};
log("debug", "initializing internal_jwt authentication provider for host '%s'", host);

function provider.test_password(username, password)
	log("debug", "test password for user %s at host %s", username, host);
	local credentials = accounts:get(username) or {};

	if password == credentials.password then
		return true;
	elseif password:match("^[^%.]+%.[^%.]+%.[^%.]+$") then
		payload, type = jwt.parse(password, signing_secret)
		jid = username .. "@" .. host;
		if payload.jid == jid then
			log("info", "JWT auth complete for %s", username)
			return true;
		else
			log("info", "JWT auth failed for %s", username)
			return nil, "Invalid token";
		end
	else
		return nil, "Auth failed. Invalid username or password.";
	end
end

function provider.set_password(username, password)
	local account = accounts:get(username);
	if account then
		account.password = password;
		return accounts:set(username, account);
	end
	return nil, "Account not available.";
end

function provider.user_exists(username)
	log("debug", "user_exists(%s)", username)
	local account = accounts:get(username);
	if not account then
		log("debug", "account not found for username '%s' at host '%s'", username, host);
		return nil, "Auth failed. Invalid username";
	end
	return true;
end

function provider.users()
	return accounts:users();
end

function provider.create_user(username, password)
	return accounts:set(username, {password = password});
end

function provider.delete_user(username)
	return accounts:set(username, nil);
end

function provider.get_sasl_handler()
    local testpass_authentication_profile = {
            plain_test = function(sasl, username, password, realm)
                    return usermanager.test_password(username, realm, password), true;
            end,
    };
	return new_sasl(host, testpass_authentication_profile);
end
	
module:provides("auth", provider);

