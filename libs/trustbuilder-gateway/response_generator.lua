--
-- Created by IntelliJ IDEA.
-- User: gerry
-- Date: 15/02/2017
-- Time: 20:10
-- To change this template use File | Settings | File Templates.
--


local setmetatable      = setmetatable
local ngx               = ngx
local gw_conf           = require "trustbuilder-gateway.configuration"
local ngx_escape_uri    = ngx.escape_uri

local conf,conf_err = gw_conf:new()
if not conf then
    ngx.log(ngx.ERR,conf_err)
    ngx.exit(500)
end

local function returnRedirectStatus()
    if ngx.req.get_headers()["X-Requested-With"] then
        return 409
    else
        return ngx.HTTP_SEE_OTHER
    end
end

local function construct_www_authenticate_header(errorCode)
    if errorCode then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. ngx.var.server_name .. '", error=\"' .. errorCode .. '\"'
    end
end

local ResponseGenerator = {}
ResponseGenerator.__index = ResponseGenerator

setmetatable(ResponseGenerator, {
    __call = function (cls, ...)
        return cls.new(...)
    end,
})

ResponseGenerator.httpAuthRequired = function(errorCode)
    construct_www_authenticate_header(errorCode)
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

ResponseGenerator.httpAccessDenied = function(errorCode)
    construct_www_authenticate_header(errorCode)

    ngx.exit(403)
end

ResponseGenerator.httpBadRequest = function(errorCode)
    construct_www_authenticate_header(errorCode)
    ngx.exit(400)
end

ResponseGenerator.webAppRedirectToLogin = function(operation,principal,extravars)
    local login_url = conf.login_url

    ngx.log(ngx.DEBUG, "Redirect to " .. login_url .. " with operation " .. operation)
    ngx.header["Location"] = login_url .. "?operation=".. operation .. "&ref=" .. ngx_escape_uri(ngx.var.request_uri)

    if principal then
        ngx.header["Location"] = ngx.header["Location"] .. "&principal=" .. ngx_escape_uri(principal)
    end

    -- Set extra keys if present
    if extravars then
        for key,value in pairs(extravars) do
            ngx.header["Location"] = ngx.header["Location"] .. "&" .. key .. "=" .. value
        end
    end

    ngx.exit(returnRedirectStatus())
end

ResponseGenerator.webAccessDenied = function(extravars)
        local vars = extravars or {}
        vars.reason = "Deny"
        ResponseGenerator.webAppRedirectToLogin("error", nil, vars)
end

return ResponseGenerator