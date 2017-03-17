--
-- Created by IntelliJ IDEA.
-- User: gerry
-- Date: 15/02/2017
-- Time: 14:23
-- To change this template use File | Settings | File Templates.
--

local setmetatable, pcall = setmetatable, pcall
local ngx = ngx
local cjson = require "cjson"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local gw_conf = require "trustbuilder-gateway.configuration"
local responseGenerator = require "trustbuilder-gateway.response_generator"
local PrincipalDao = require "trustbuilder-gateway.dao.principal"
local ngx_encode_base64 = ngx.encode_base64


local conf, conf_err = gw_conf:new()
if not conf then
    ngx.log(ngx.ERR,conf_err)
    ngx.exit(500)
end

local function generateAuthorizationError(message)
    ngx.log(ngx.ERR,"Authorization Error: " .. message)
    ngx.exit(500)
end

local function sha256(value)
    ngx.log(ngx.DEBUG, ">>>> sha256")

    local sha256 = resty_sha256:new()
    sha256:update(value)
    local digest = sha256:final()
    return str.to_hex(digest)
end

local function determine_cache_key()
    ngx.log(ngx.DEBUG, ">>>> determine_cache_key")

    ngx.log(ngx.DEBUG,"Determing Cache Key")
    local cacheKey = ngx.ctx.sessionId
    if ngx.ctx.session and ngx.ctx.session.authzIndex then
        cacheKey = ngx.ctx.session.authzIndex
    elseif ngx.ctx.cacheKey and ngx.req.get_headers()[ngx.ctx.cacheKey] then
        cacheKey = sha256(ngx.req.get_headers()[ngx.ctx.cacheKey])
    end

    if cacheKey then
        ngx.log(ngx.DEBUG,"Cache Key: " .. cacheKey)
    end
    return cacheKey
end

local function set_caching_response_header(status)
    ngx.log(ngx.DEBUG, ">>>> set_caching_response_header")

    ngx.log(ngx.DEBUG,"Cache Response: " .. status)
    ngx.header["x-tb-azn-cache"] = status
end

local function get_cached_azn_result(request_uri, request_method)
    ngx.log(ngx.DEBUG, ">>>> get_cached_azn_result")

    local sessionid = determine_cache_key()
    if not sessionid then
        return nil, "NOCACHEKEY"
    end

    local azn_cache = ngx.shared.aznCache
    local cache_key = sessionid .. ":" .. request_method .. ":" .. request_uri

    if not azn_cache then
        ngx.log(ngx.WARN,"No Authorization cache is enabled")
        return nil, "NOTENABLED"
    end

    ngx.log(ngx.DEBUG,"Fetch cache for " .. cache_key)
    local cache_result = azn_cache:get(cache_key)
    if cache_result then
        ngx.log(ngx.DEBUG,"Cache hit " .. cache_result)
        local status, cached_azn_result = pcall(cjson.decode, cache_result)
        -- If there is a wrong result in cache dat could be decoded
        if not cached_azn_result then
            ngx.log(ngx.WARN,"Deleting wrong cached result")
            azn_cache.del(cache_key)
            return nil, "WRONGCACHE"
        else
            return cached_azn_result
        end
    else
        return nil, "NOCACHEHIT"
    end
end

local function store_azn_result_in_cache(azn_result, ttl)
    ngx.log(ngx.DEBUG, ">>>> store_azn_result_in_cache")

    --- Check if the cacheKey was overwritten (important for api, they put it on a header)
    local sessionid = determine_cache_key()
    if not sessionid then
        return nil, "NOCACHEKEY"
    end

    local azn_cache = ngx.shared.aznCache
    local cache_key = sessionid .. ":" .. ngx.var.request_method .. ":" .. ngx.var.request_uri
    local ttl = ttl

    if not azn_cache then
        ngx.log(ngx.WARN,"No Authorization cache is enabled")
        return nil, "NOCACHE"
    end


    ngx.log(ngx.DEBUG,"Saving in cache. TTL: " .. ttl)
    --- Adding isCached to check later on
    azn_result.isCached = true

    --- Adding the userSessionId for later retrieval
    azn_result.principalSessionId = ngx.ctx.principalSessionId

    local ok, err = azn_cache:add(cache_key, cjson.encode(azn_result), ttl)
    if not ok and err ~= "exists" then
        ngx.log(ngx.WARN,"Could not set cache: " .. err)
    elseif err == "exists" then
        ngx.log(ngx.DEBUG,"Key exists, not overwriting")
    end
end

local function get_subrequest_azn_result(authzLocation)
    ngx.log(ngx.DEBUG, ">>>> get_subrequest_azn_result")

    ngx.log(ngx.DEBUG,"Start Request: " .. authzLocation)
    cjson.encode_empty_table_as_object(false)
    local aznRequestInHeaders = ngx.ctx.aznInHeaders or conf.azn_in_headers
    local options = {}
    local result = {
        score = 0
    }

    local principalSession = ngx.ctx.principalSession or { principal = "" }
    --- DO THE INTERNAL REQUEST
    ngx.log(ngx.DEBUG,"AZNIN headers: ", aznRequestInHeaders);
    if aznRequestInHeaders == "true" then
        ngx.req.set_header("X-TB-AUTH-URI", ngx.var.request_uri)
        ngx.req.set_header("X-TB-AUTH-LOC", ngx.ctx.reqLocation)
        ngx.req.set_header("X-TB-SESSION", ngx_encode_base64(cjson.encode({
            credential = principalSession
        })))
        ngx.req.set_header("X-TB-AUTH-TYPE", ngx.ctx.requestType)
        ngx.req.set_header("X-TB-AUTH-METHOD", ngx.var.request_method)

        options = {
            method = ngx.HTTP_POST,
            body = ""
        }
    else

        options = {
            method = ngx.HTTP_POST,
            body = cjson.encode({
                type = ngx.ctx.requestType,
                location = ngx.ctx.reqLocation,
                request_uri = ngx.var.request_uri,
                request_headers = ngx.req.get_headers(),
                request_method = ngx.var.request_method,
                credential = principalSession
            })
        }
    end

    local authz_res, error = ngx.location.capture(authzLocation, options)
    if authz_res and authz_res.status == 200 then
        local azn_result = authz_res.body
        --- REMOVE: This if can be removed if the authorization controller has changed to the new way of working
        if aznRequestInHeaders == "true" then
            azn_result = authz_res.header["X-TB-AZN"]

            ngx.req.clear_header("TB_AUTH_URI")
            ngx.req.clear_header("TB_AUTH_LOC")
            ngx.req.clear_header("TB_SESSION")
            ngx.req.clear_header("X-TB-AUTH-TYPE")
            ngx.req.clear_header("X-TB-AUTH-SCOPES")
            ngx.req.clear_header("X-TB-AUTH-METHOD")
            ngx.req.clear_header("X-TB-AUTH-URI")
            ngx.req.clear_header("X-TB-AUTH-LOC")
        end
        ngx.log(ngx.DEBUG, "Retrieved AZN Result: ", azn_result)
        if azn_result then
            local decodeStatus, decodeResult = pcall(cjson.decode, azn_result)
            if decodeStatus == false then
                ngx.log(ngx.DEBUG,"Cannot JSON decode authorization result")
            end
            result = decodeResult
        else
            ngx.log(ngx.DEBUG,"Empty AZN Result received")
        end

    else
        ngx.log(ngx.DEBUG,"Unkown result returned from authorization Location")
    end


    return result
end



local function get_authentication_status(user_credential, location)
    ngx.log(ngx.DEBUG, ">>>> get_authentication_status")

    local authzLocations = user_credential.authzLocations

    if not authzLocations then
        return false
    end

    for _, value in pairs(authzLocations) do
        if value == location then
            return true
        end
    end
end

local function save_user_session(authzResult)
    ngx.log(ngx.DEBUG, ">>>> save_user_session")
    --- Saving is only when it is present (and it is not always present)

    if authzResult.principal then
        local principalDao = PrincipalDao:new()
        if not principalDao then
            generateAuthorizationError("Error creating Principal DAO")
        end


        ngx.ctx.principalSession = authzResult.principal
        local principalId, principalSaveErr = principalDao:save(authzResult.principal ,nil, conf.session_timeout) --- The middle nil is the credentialIndex, will be always nil in this case
        if not principalId then
            generateAuthorizationError("Princial save failed: " .. principalSaveErr)
        end

        ngx.ctx.principalSessionId = principalId
    else
        ngx.log(ngx.DEBUG,"No principal found to save")
    end
end

local function get_user_session(authzResult)
    ngx.log(ngx.DEBUG, ">>>> get_user_session")

    if not ngx.ctx.principalSession then
        --- Fetch the principal session
        local principalDao = PrincipalDao:new()
        if not principalDao then
            generateAuthorizationError("Error creating Principal DAO")
        end

        if authzResult.principal then
            ngx.ctx.principalSession = authzResult.principal
        end

        if authzResult.principalSessionId then
            ngx.ctx.principalSessionId = authzResult.principalSessionId
        end

        if not ngx.ctx.principalSession and ngx.ctx.principalSessionId then
            ngx.ctx.principalSession = principalDao:get(ngx.ctx.principalSessionId)
        else
            --- Create Empty principal
            ngx.ctx.principalSession = {
                principal = ""
            }
        end
    end
end

local function handle_failed_web_app_response(authzResult)
    ngx.log(ngx.DEBUG, ">>>> handle_failed_web_app_response")

    local extradata = {}
    local reason = authzResult.reason
    local operation = "error"
    local principal

    if reason == "ReAuthenticate" then
        operation = "reauthenticate"
    elseif reason == "StepUp" then
        operation = "stepup"

        extradata = {
            method = authzResult.method,
            comparison = authzResult.comparison
        }
    else
        extradata = authzResult.info or {}
    end

    if ngx.ctx.principalSession then
        principal = ngx.ctx.principalSession.principal
    end

    responseGenerator.webAppRedirectToLogin(operation, principal, extradata)
end

local function handle_failed_api_response(authzResult)
    ngx.log(ngx.DEBUG, ">>>> handle_failed_api_response")
    local reason = authzResult.reason

    if reason == "invalid_token" then
        responseGenerator.httpAuthRequired(reason)
    elseif reason == "invalid_request" then
        responseGenerator.httpBadRequest(reason)
    else
        responseGenerator.httpAccessDenied(reason)
    end
end

local function handle_failed_authorization(authzResult)
    ngx.log(ngx.DEBUG, ">>>> handle_failed_authorization")
    if ngx.ctx.requestType == "WEB_APP" then
        handle_failed_web_app_response(authzResult)
    else
        handle_failed_api_response(authzResult)
    end
end

local function validate_authorization_result(authzResult)
    ngx.log(ngx.DEBUG, ">>>> validate_authorization_result")
    if authzResult.isCached then
        ngx.log(ngx.DEBUG,"Cached authorization result")
        get_user_session(authzResult)
    else
        if authzResult.score == 1 then
            local cacheTtl = authzResult.cache or conf.authorization_cache_time
            save_user_session(authzResult)
            store_azn_result_in_cache(authzResult, cacheTtl)
        else
            handle_failed_authorization(authzResult)
        end
    end
end


local Authorization = {}
Authorization.__index = Authorization

setmetatable(Authorization, {
    __call = function(cls, ...)
        return cls.new(...)
    end,
})

Authorization.authorize = function(authzLocation)
    ngx.log(ngx.DEBUG, ">>>> Authorization.authorize for ", ngx.ctx.requestType)
    local userSession = ngx.ctx.principalSession
    local authorizationResult


    if ngx.ctx.requestType ~= "API" then
        --- Only for web at the moment, should be moved to the authorization controller as well then just remove this if
        --- This will test if the location is already in the session, if not redirect to orchestrator to make sure he is authorized
        if userSession then
            local applicationAuthResult = get_authentication_status(userSession, ngx.ctx.reqLocation)
            if applicationAuthResult == false and ngx.ctx.requestType == "WEB_APP" then
                --- Need to do a redirect to the gw-login
                responseGenerator.webAppRedirectToLogin("login", userSession.principal);
            end
        end
    end

    --- Fetch cache
    local cachedResult, cacheError = get_cached_azn_result(ngx.var.request_uri, ngx.var.request_method)
    if cachedResult then
        set_caching_response_header("CACHEHIT")
        authorizationResult = cachedResult
    else
        set_caching_response_header(cacheError)
        local subRequest, requestError = get_subrequest_azn_result(authzLocation)
        if not subRequest then
            ngx.log(ngx.DEBUG,"Error from SubRequest: " .. requestError)
            responseGenerator.accessDenied(ngx.ctx.requestType)
        else
            authorizationResult = subRequest
        end
    end

    validate_authorization_result(authorizationResult, ngx.ctx.requestType)
end

return Authorization