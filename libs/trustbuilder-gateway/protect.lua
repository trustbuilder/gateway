local ngx_escape_uri                    = ngx.escape_uri
local ngx_unescape_uri                  = ngx.unescape_uri
local ngx_exit                          = ngx.exit
local ngx_encode_base64                 = ngx.encode_base64
local ngx_decode_base64                 = ngx.decode_base64
local setmetatable, pcall               = setmetatable, pcall
local cjson                             = require "cjson.safe"
local string_helpers                    = require "trustbuilder-gateway.helpers.string"
local gw_conf                           = require "trustbuilder-gateway.configuration"
local authorization                     = require "trustbuilder-gateway.authorization"
local authentication                    = require "trustbuilder-gateway.authentication"

local conf,conf_err = gw_conf:new()
if not conf then
  ngx.log(ngx.ERR,conf_err)
  ngx_exit(500)
end


local function set_common_headers(cred_index,cred)
  ngx.req.set_header("x-tb-session", ngx_encode_base64(cjson.encode(cred)))
  ngx.req.set_header("x-tb-credentialindex", cred_index)
  ngx.req.set_header("tb-user", cred.principal)
  ngx.log(ngx.DEBUG,"SETTING x-tb-session: " .. ngx_encode_base64(cjson.encode(cred)))
  ngx.log(ngx.DEBUG,"SETTING x-tb-credentialindex: " .. cred_index)
  ngx.log(ngx.DEBUG,"SETTING tb-user: " .. cred.principal)
end

local function create_backendheaders(credindex, cred,location,headersoverride)
  -- Define functions to use when creating headers
  local sandbox = {
    credential = cred,
    location = location,
    credential_index = credindex,
    b64 = {
      encode = ngx_encode_base64,
      decode= ngx_decode_base64
    },
    now = ngx.now,
    uri = {
      escape = ngx_escape_uri,
      unescape = ngx_unescape_uri
    }
  }
  local sandboxmeta = { __index={}, __newindex = function() end  }
  setmetatable(sandbox,sandboxmeta)

  local function run_attr(code)
    local f = assert(loadstring("return " .. code))
    setfenv(f,sandbox)
    local status, result = pcall(f)
    if status == false then
      ngx.log(ngx.WARN, "Header code failed: " .. result)

      return "NOT_FOUND"
    end

    return result
  end

  set_common_headers(credindex,cred)

  if headersoverride then
    for k,v in pairs(headersoverride) do
      ngx.req.set_header(k:gsub("%_", "-"), run_attr(v))
    end
  end

end


local function clear_frontend_headers()
  -- clear headers that are incoming
  ngx.req.clear_header("x-tb-session")
  ngx.req.clear_header("x-tb-credentialindex")
  ngx.req.clear_header("tb-user")
end

local _M = {}
_M.__index = _M

setmetatable(_M, {
  __call = function (cls, ...)
    return cls.new(...)
  end,
})

function _M.web_app(headers, authz_location)
  local config = {}

  if headers then
    config.headers = headers
  end

  if authz_location then
    config.location = authz_location
  end

  _M.web_app_v2(config)
end

_M.public_web_app = function(headers, authz_location, authorization)
  local config = {}

  if headers then
    config.headers = headers
  end

  if authz_location then
    config.location = authz_location
  end

  if authorization then
    config.authorizationRequired = authorization
  end

  _M.public_web_app_v2(config)
end

function _M.api(headers, authz_location)
  local config = {

  }

  if headers then
    config.headers = headers
  end

  if authz_location then
    config.location = authz_location
  end

  _M.api_v2(config)
end


function _M.orchestrator()
  clear_frontend_headers()

  local req_uri = ngx.var.uri

  if string_helpers.starts(req_uri, "/idhub/admin/api") then
    ngx.log(ngx.DEBUG, "Admin API call")
    -- This should become oauth and another location
    if conf.idhub_admin_api_enabled == "false" or conf.idhub_admin_enabled == "false" then
      ngx_exit(403)
    end
    _M.web_app(nil,"/idhub/admin")
  elseif string_helpers.starts(req_uri, "/idhub/selfservice/api") then
    -- This should become oauth and another location
    ngx.log(ngx.DEBUG, "SelfService API call")
    _M.web_app(nil,"/idhub/selfservice")
  elseif string_helpers.starts(req_uri, "/idhub/installation") then
    ngx.log(ngx.DEBUG, "Install call")
    if conf.idhub_install_enabled == "false" then
      ngx_exit(403)
    end
  elseif string_helpers.starts(req_uri, "/idhub/admin") then
    ngx.log(ngx.DEBUG, "Admin call :" .. conf.idhub_admin_enabled)
    if conf.idhub_admin_enabled == "false" then
      ngx_exit(403)
    end
    _M.web_app(nil,"/idhub/admin")
  elseif string_helpers.starts(req_uri, "/idhub/selfservice") then
    ngx.log(ngx.DEBUG, "SelfService call")
    _M.web_app(nil,"/idhub/selfservice")
  elseif string_helpers.starts(req_uri, "/idhub/install") then
    ngx.log(ngx.DEBUG, "Install call")
    if conf.idhub_install_enabled == "false" then
      ngx_exit(403)
    end
  elseif string_helpers.starts(req_uri, "/idhub/static") then
    ngx.log(ngx.DEBUG, "Anonymous Call")
  else
    ngx.log(ngx.DEBUG, "Public call")
    _M.public_web_app()
  end

end

_M.api_v2 = function(config)
  local headerConfig = {}
  local authzLocation = conf.authorization_url
  ngx.ctx.cacheKey = "Authorization"
  ngx.ctx.requestType = "API"

  if config then
    ngx.log(ngx.DEBUG,"Local Configuration found")
    headerConfig = config.headers or {}
    ngx.ctx.reqLocation = config.location or ngx.var.location
    authzLocation = config.authzLocation or conf.authorization_url
    ngx.ctx.cacheKey = config.cacheKeyHeader or "Authorization"
    ngx.ctx.aznInHeaders = config.aznInHeaders or conf.azn_in_headers
  end

  -- Make sure that they cannot send any frontend headers that are "restricted"
  clear_frontend_headers()

  authorization.authorize(authzLocation)

  -- Create Backend headers
  create_backendheaders(ngx.ctx.principalSessionId, ngx.ctx.principalSession, ngx.ctx.reqLocation,headerConfig)
end

_M.web_app_v2 = function(config)
  local headerConfig = {}
  local authzLocation = conf.authorization_url
  ngx.ctx.requestType = "WEB_APP"

  if config then
    ngx.log(ngx.DEBUG,"Local Configuration found")
    headerConfig = config.headers or {}
    ngx.ctx.reqLocation = config.location or ngx.var.location
    authzLocation = config.authzLocation or conf.authorization_url
    ngx.ctx.aznInHeaders = config.aznInHeaders or conf.azn_in_headers
  end

  clear_frontend_headers()

  authentication.validateSession(true)

  authorization.authorize(authzLocation)

  create_backendheaders(ngx.ctx.principalSessionId, ngx.ctx.principalSession, ngx.ctx.reqLocation,headerConfig)
end

_M.public_web_app_v2 = function(config)
  local headerConfig = {}
  local authzLocation = conf.authorization_url
  local authorizationRequired = false
  ngx.ctx.requestType = "PUBLIC_WEB_APP"

  if config then
    ngx.log(ngx.DEBUG,"Local Configuration found")
    headerConfig = config.headers or {}
    ngx.ctx.reqLocation = config.location or ngx.var.location
    authzLocation = config.authzLocation or conf.authorization_url
    ngx.ctx.aznInHeaders = config.aznInHeaders or conf.azn_in_headers
    authorizationRequired = config.authorizationRequired
  end

  clear_frontend_headers()

  authentication.validateSession(false)

  if authorizationRequired then
    authorization.authorize(authzLocation)
  end

  if ngx.ctx.principalSession then
    create_backendheaders(ngx.ctx.principalSessionId, ngx.ctx.principalSession, ngx.ctx.reqLocation,headerConfig)
  end

end

return _M
