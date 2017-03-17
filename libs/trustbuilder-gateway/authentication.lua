--
-- Created by IntelliJ IDEA.
-- User: gerry
-- Date: 13/03/2017
-- Time: 13:35
-- To change this template use File | Settings | File Templates.
--

local setmetatable, pcall   = setmetatable, pcall
local ngx                   = ngx
local cjson                 = require "cjson.safe"
local resty_sha256          = require "resty.sha256"
local resty_aes             = require "resty.aes"
local str                   = require "resty.string"
local gw_conf               = require "trustbuilder-gateway.configuration"
local responseGenerator     = require "trustbuilder-gateway.response_generator"
local PrincipalDao          = require "trustbuilder-gateway.dao.principal"
local SessionDao            = require "trustbuilder-gateway.dao.session"
local ngx_encode_base64     = ngx.encode_base64
local ngx_decode_base64     = ngx.decode_base64
local ck                    = require "resty.cookie"
local random                = require "trustbuilder-gateway.helpers.random"


local ENCODE_CHARS = {
    ["+"] = "-",
    ["/"] = "_",
    ["="] = "."
}

local DECODE_CHARS = {
    ["-"] = "+",
    ["_"] = "/",
    ["."] = "="
}

local base64_cookie_encode = function(value)
    return (ngx_encode_base64(value):gsub("[+/=]", ENCODE_CHARS))
end

local base64_cookie_decode = function (value)
    return ngx_decode_base64((value:gsub("[-_.]", DECODE_CHARS)))
end

local function sha256(value, base64)
    ngx.log(ngx.DEBUG, ">>>> sha256")
    local result
    local sha256 = resty_sha256:new()
    sha256:update(value)
    local digest = sha256:final()

    if base64 then
        result = ngx_encode_base64(digest)
    else
        result = str.to_hex(digest)
    end
    return result
end


local conf, conf_err = gw_conf:new()
if not conf then
    ngx.log(ngx.ERR, conf_err)
    ngx.exit(500)
end

local generateAuthenticationError = function(message)
    ngx.log(ngx.ERR, "Authentication Error: " .. message)
    ngx.exit(500)
end

local getSessionCookieValue = function()
    ngx.log(ngx.DEBUG, ">>>> getSessionCookieValue")
    if not ngx.ctx.sessionId then

        local cookie, cookie_err = ck:new()
        local cookieName = conf.session_cookie

        if not cookie then
            generateAuthenticationError(cookie_err)
        end

        local ok, err = cookie:get(cookieName)

        if not ok then
            ngx.log(ngx.DEBUG, "Cookie failed: " .. err)
            return nil
        else
            ngx.ctx.sessionId = ok
            return ok
        end
    else
        return ngx.ctx.sessionId
    end
end

local getCredentialCookieValue = function()
    ngx.log(ngx.DEBUG, ">>>> getCredentialCookieValue")
    local cookie, cookie_err = ck:new()
    local cookieName = conf.credential_fallback_cookie
    local cookieValue

    if not cookie then
        generateAuthenticationError(cookie_err)
    end

    local ok,err = cookie:get(cookieName)
    if not ok then
        ngx.log(ngx.DEBUG, "Cookie failed: ", err)
        return nil
    else
        -- Do some decrypt stuff here TODO!
        -- Determine salt

        local salt = ngx.var.ssl_session_id
        if conf.credential_fallback_salt_session_cookie then
            ngx.log(ngx.DEBUG, "Using session cookie as SALT")
            salt = ngx.ctx.sessionId
        end
        local encryptKey = conf.session_password

        -- Create encryption
        local aes_256_cbc_sha512x5 = resty_aes:new(encryptKey, salt, resty_aes.cipher(256,"cbc"), resty_aes.hash.sha512,5)

        cookieValue = cjson.decode(aes_256_cbc_sha512x5:decrypt(base64_cookie_decode(ok)))
    end

    return cookieValue
end

local removeCredentialCookie = function()
    ngx.log(ngx.DEBUG, ">>>> removeCredentialCookie")
    local cookie, cookie_err = ck:new()
    local cookieName = conf.credential_fallback_cookie

    local ok,err = cookie:set({
        key = cookieName,
        expires = ngx.cookie_time(ngx.time() - 300),
        value = "",
        path = "/",
        httponly = true,
        secure = true
    })

    if not ok then
        ngx.log(ngx.DEBUG, "Cookie delete failed: " .. err)
        return nil
    end
end

local generateSessionCookie = function(redirectIfNotExist)
    ngx.log(ngx.DEBUG, ">>>> generateSessionCookie")
    local cookie, cookie_err = ck:new()

    if not cookie then
        generateAuthenticationError(cookie_err)
    end

    if ngx.ctx.sessionCookieSet ~= true then

        local session_cookie = conf.session_cookie
        local token = random.token(32)

        local ok, err = cookie:set({
            key = session_cookie,
            value = token,
            path = "/",
            httponly = true,
            secure = true
        })

        if not ok then
            ngx.log(ngx.ERR, err)
            ngx.exit(500)
        end

        ngx.log(ngx.DEBUG, "Setting cookie " .. session_cookie .. " to " .. token)
        ngx.ctx.sessionCookieSet = true
        ngx.ctx.sessionId = token
    end

    if redirectIfNotExist == true then
        responseGenerator.webAppRedirectToLogin("login")
    end
end

local decodeAuthHeaderValue = function(value)
    ngx.log(ngx.DEBUG, ">>>> decodeAuthHeaderValue")
    local b64Ok,b64Session = pcall(ngx.decode_base64, value)
    if not b64Ok then
        return nil, "BASE64_DECODE_FAILED"
    end

    local decodeSession, decodeErr = cjson.decode(b64Session)
    if not decodeSession then
        return nil, decodeErr
    end

    return decodeSession
end


local Authentication = {}
Authentication.__index = Authentication

setmetatable(Authentication, {
    __call = function(cls, ...)
        return cls.new(...)
    end,
})

Authentication.generateSessionCookie = function()
    generateSessionCookie(false)
end

Authentication.getSessionCookieValue = function()
    return getSessionCookieValue()
end

Authentication.removeSessionCookie = function()
    local cookie, cookie_err = ck:new()
    local cookieName = conf.session_cookie

    local ok,err = cookie:set({
        key = cookieName,
        expires = ngx.cookie_time(ngx.time() - 300),
        value = "",
        path = "/",
        httponly = true,
        secure = true
    })

    if not ok then
        ngx.log(ngx.DEBUG, "Cookie delete failed: " .. err)
        return nil
    end
end

Authentication.saveSessionInCookie = function(authHeaderValue, opts)
    ngx.log(ngx.DEBUG, ">>>> Authentication.saveSessionInCookie")
    local cookie, cookie_err = ck:new()
    local sessionId
    local cookieValue = {}
    cjson.encode_empty_table_as_object(false)

    if not cookie then
        generateAuthenticationError(cookie_err)
    end

    -- Determine salt
    local salt = ngx.var.ssl_session_id
    if conf.credential_fallback_salt_session_cookie then
        ngx.log(ngx.DEBUG, "Using session cookie as SALT")
        salt = ngx.ctx.sessionId
    end
    local encryptKey = conf.session_password

    -- Create encryption
    local aes_256_cbc_sha512x5 = resty_aes:new(encryptKey, salt, resty_aes.cipher(256,"cbc"), resty_aes.hash.sha512,5)


    -- Validate authHeader
    local decodedValue, decodeError = decodeAuthHeaderValue(authHeaderValue)
    if not decodedValue then
        ngx.log(ngx.WARN, "AUTHENTICATION Failed:" .. decodeError)
        return nil
    end


    -- Create Cookie Logic
    cookieValue.credentialIndex = opts.credentialIndex
    cookieValue.credentialTtl = opts.credentialTtl or conf.session_timeout
    cookieValue.sessionTtl = opts.sessionTtl or conf.session_inactivity_timeout
    -- Set my cookie value
    cookieValue.credential = decodedValue

    -- Encrypt cookie
    local encryptedCookieValue = base64_cookie_encode(aes_256_cbc_sha512x5:encrypt(cjson.encode(cookieValue)))

    ngx.log(ngx.DEBUG, "Encrypted Cookie: ", encryptedCookieValue)
    -- Set cookie
    local cookieOk, cookieErr = cookie:set({
        key = conf.credential_fallback_cookie,
        value = encryptedCookieValue,
        path = "/",
        httponly = true,
        secure = true
    })

    if not cookieOk then
        ngx.log(ngx.ERR, cookieErr)
        ngx.exit(500)
    end
end

local saveSessionInRedis = function(sessionId, sessionData)
    ngx.log(ngx.DEBUG, ">>>> saveSessionInRedis")
    local sessionDao = SessionDao:new(conf)
    local principalDao = PrincipalDao:new(conf)
    local session,sessionSaveErr

    local credentialIndex,principalSaveErr = principalDao:save(sessionData.credential, sessionData.credentialIndex, sessionData.credentialTtl)
    if not credentialIndex then
        generateAuthenticationError("Princial save failed: " .. principalSaveErr)
    end


    -- Add the credentialIndex to the session data
    if not sessionData.credentialIndex then
        sessionData.credentialIndex = credentialIndex
    end

    -- Save the session
    session, sessionSaveErr = sessionDao:save(sessionId,sessionData)
    if not session then
        generateAuthenticationError("Session save failed: " .. sessionSaveErr)
    end

    -- Save the session already in the ngx.ctx
    ngx.ctx.principalSession = sessionData.credential
    ngx.ctx.principalSessionId = credentialIndex
    return session
end


Authentication.validateSession = function(redirectIfNotExist)
    ngx.log(ngx.DEBUG, ">>>> Authentication.validateSession")
    local sessionDao = SessionDao:new(conf)
    local principalDao = PrincipalDao:new(conf)
    local sessionId = getSessionCookieValue()
    local session

    if not sessionId then
        generateSessionCookie(redirectIfNotExist)
    end

    local sessionToSave = getCredentialCookieValue()
    --- At this point we have a session that we can save.
    if sessionToSave then
        session = saveSessionInRedis(ngx.ctx.sessionId,sessionToSave)
        removeCredentialCookie()
    else
        session = sessionDao:get(sessionId)
    end

    if not session then
        -- check if a cookie authentication is available
        generateSessionCookie(redirectIfNotExist)
    else
        ngx.log(ngx.DEBUG, "Session: " .. cjson.encode(session))
        ngx.ctx.session = session
    end

    --- If we did not fetch principalsession do it now if we have a session available and credential index
    if not ngx.ctx.principalSession and session and session.credentialindex then
        local principal, principalError = principalDao:get(session.credentialindex)
        if not principalError then
            --- If we can fetch the principal we do so here. this can be used in the remainder of this request
            ngx.log(ngx.DEBUG, "Setting principal: " .. cjson.encode(principal))
            ngx.ctx.principalSession = principal
            ngx.ctx.principalSessionId = session.credentialindex
        else
            ngx.log(ngx.DEBUG, "Get principal failed. GenerateSessionCookie and redirect: ", redirectIfNotExist)
            generateSessionCookie(redirectIfNotExist)
        end
    end


    return true
end

Authentication.removeSession = function(premature, configuration, session, sessionid)
    if premature then
        -- thread is done, worker in shutdown mode
        return
    end

    local sessionDao = SessionDao:new(configuration)
    local principalDao = PrincipalDao:new(configuration)

    ngx.log(ngx.DEBUG, "Removing Session with ID: ", sessionid)

    local credentialIndex = session.credentialindex

    local principalDeleteOk, principalDeleteErr = principalDao:delete(credentialIndex)
    if not principalDeleteOk then
        ngx.log(ngx.WARN, "Could not remove principal with: ", credentialIndex)
    end

    local sessionDeleteOk, sessionDeleteErr = sessionDao:delete(sessionid)
    if not sessionDeleteOk then
        ngx.log(ngx.WARN, "Could not remove session with: ", sessionid)
    end

end


return Authentication