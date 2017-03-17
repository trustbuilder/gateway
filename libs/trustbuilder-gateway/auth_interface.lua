local ipairs            = ipairs
local ngx               = ngx
local string_helpers    = require "trustbuilder-gateway.helpers.string"
local gw_conf           = require "trustbuilder-gateway.configuration"
local authentication    = require "trustbuilder-gateway.authentication"

local ngx_exit = ngx.exit


local conf, conf_err = gw_conf:new()
if not conf then
    ngx.log(ngx.ERR, conf_err)
    ngx_exit(500)
end


local function is_allowed_contenttype(headerval)
    local allowed_types = {
        "text/html",
        "text/xml",
        "text/plain",
        "application/json",
        "application/soap",
        "application/xml"
    }

    for _, val in ipairs(allowed_types) do
        if string_helpers.starts(headerval, val) then
            return true
        end
    end

    return nil
end

local function validate_authentication_request()
    ngx.log(ngx.DEBUG, "Validating Authentication Interface")
    if ngx.status >= 200 and ngx.status < 300 then
        ngx.log(ngx.DEBUG, "HTTP-Status: " .. ngx.status .. " // Checking Content-Type")
        if ngx.header["content-type"] and is_allowed_contenttype(ngx.header["content-type"]) then
            ngx.log(ngx.DEBUG, "Content-Type valid")
            return true
        end
    elseif ngx.status >= 300 and ngx.status < 400 then
        ngx.log(ngx.DEBUG, "redirect status found: " .. ngx.status)
        return true
    else
        ngx.log(ngx.DEBUG, "No valid HTTP status found for authentication_interface")
    end

    return nil
end

local function clear_auth_headers()
    ngx.header["X-TB-AUTH"] = nil
    ngx.header["X-TB-SESSION"] = nil
    ngx.header["X-TB-EXPIRES-IN"] = nil
    ngx.header["X-TB-CREDENTIAL-TTL"] = nil
    ngx.header["X-TB-CREDENTIAL-ID"] = nil
    ngx.header["X-TB-OAUTH-SCOPES"] = nil
end



local function authentication_interface()
    if not validate_authentication_request() then
        clear_auth_headers()
        ngx.log(ngx.DEBUG, "Ignoring Authentication Interface, Not a valid request")
        return
    end

    ngx.log(ngx.DEBUG, "Start Authentication flow")
    local sessionId = ngx.ctx.sessionId or authentication.getSessionCookieValue()
    local sessionIdHeader = ngx.header["X-TB-SESSION"]

    if not sessionId then
        if not sessionIdHeader then
            authentication.generateSessionCookie()
        else
            sessionId = sessionIdHeader
        end
    end


    local auth_hdr = ngx.header["X-TB-AUTH"]
    local existing_cred = ngx.header["X-TB-CREDENTIAL-ID"]
    local session_expire = ngx.header["X-TB-EXPIRES-IN"]
    local credential_expire = ngx.header["X-TB-CREDENTIAL-TTL"]
    local logout_hdr = ngx.header["X-TB-LOGOUT"]
    local ssl_session_id = ngx.var.ssl_session_id

    local opts = {
        credentialIndex = existing_cred,
        sessionTtl = session_expire,
        credentialTtl = credential_expire,
        sslSessionId = ssl_session_id
    }

    if ngx.header["X-TB-CREDENTIAL-ID"] then
        ngx.log(ngx.DEBUG, "Existing Credential : " .. ngx.header["X-TB-CREDENTIAL-ID"])
    end

    if auth_hdr and not logout_hdr then
        ngx.log(ngx.DEBUG, "Starting Authentication phase with X-TB-AUTH")
        authentication.saveSessionInCookie(auth_hdr, opts);
    end

    if logout_hdr then
        ngx.log(ngx.DEBUG, "Removing Credential index")
        if logout_hdr == ngx.ctx.principalSessionId then
            ngx.timer.at(0,authentication.removeSession, conf, ngx.ctx.session, ngx.ctx.sessionId)
        end

    end

    clear_auth_headers()
end

return authentication_interface
