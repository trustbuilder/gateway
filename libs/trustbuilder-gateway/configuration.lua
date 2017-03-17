local setmetatable = setmetatable


local _M = {
  _VERSION = '0.0.1',
}
local mt = { __index = _M }

function _M:new()
  if self ~= _M then
    return nil, "First argument must be self"
  end

  local options = {
    session_timeout                         = ngx.var.session_timeout or '172800', -- 2 days if nothing is defined
    session_inactivity_timeout              = ngx.var.session_inactivity_timeout or '3600', -- 1 Hour is nothing is defined
    session_cookie                          = ngx.var.session_cookie or 'tb',
    session_password                        = ngx.var.session_auth or 'TrustBuilder12ChangePassword',
    session_pool_size                       = ngx.var.session_pool_size or 256,
    session_pool_timeout                    = ngx.var.session_pool_timeout or 60000,
    credential_fallback_cookie              = ngx.var.credential_fallback_cookie or "X-TB-CREDENTIAL",
    credential_fallback_salt_session_cookie = ngx.var.credential_fallback_salt_session_cookie or false,
    login_url                               = ngx.var.login_url or '/idhub/gw-login',
    authorization_url                       = ngx.var.authorization_url or nil,
    authorization_cache_time                = ngx.var.authorization_cache_time or '600', -- 10 Minutes
    azn_in_headers                          = ngx.var.azn_in_headers or "true",
    idhub_install_enabled                   = ngx.var.idhub_install_enabled or 'false',
    idhub_admin_enabled                     = ngx.var.idhub_admin_enabled or 'false',
    idhub_admin_api_enabled                 = ngx.var.idhub_admin_api_enabled or 'false',
    response_header_auth                    = ngx.var.response_header_auth or "X-TB-AUTH",
    response_header_credentialId            = ngx.var.response_header_credential_id or "X-TB-CREDENTIAL-ID",
    response_header_login                   = ngx.var.response_header_login or "X-TB-LOGOUT"

  }
  
  

  -- Redis sentinels
  if ngx.var.session_cluster_name and ngx.var.session_sentinels then

    local sentinel_string = ngx.var.session_sentinels
    local sentinels={}
    local index = 1

    for str in string.gmatch(sentinel_string, "([^,]+)") do
      -- Parsing the redis sentinel string
      local i = 1
      local sentinel = {}
      for part in string.gmatch( str, "([^:]+)") do
        if i == 1 then
          ngx.log(ngx.DEBUG,"Add host: " .. part)
          sentinel.host = part
        end
        if i == 2 then
          ngx.log(ngx.DEBUG,"Add port: " .. part)
          sentinel.port = part
        end
        i = i + 1
      end
      ngx.log(ngx.DEBUG,"Host: " .. sentinel.host .. " // Port: "  .. sentinel.port)
      sentinels[index] = sentinel
      index = index + 1
    end

    options.redis_connection = {
      url = "sentinel://" .. options.session_password .. "@" .. ngx.var.session_cluster_name ..":a/0",
      sentinels = sentinels
    }
  else
    local url = "redis://".. options.session_password .."@127.0.0.1:6379/0"
    if ngx.var.session_store_location then
      url = "redis://" .. options.session_password .. "@" .. ngx.var.session_store_location.."/0"
    end
    
    options.redis_connection = {
      url = url
    }
  end


  return setmetatable(options, mt)

end

return _M