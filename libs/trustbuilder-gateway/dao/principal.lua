--
-- Created by IntelliJ IDEA.
-- User: gerry
-- Date: 23/02/2017
-- Time: 09:31
-- To change this template use File | Settings | File Templates.
--

local setmetatable, pcall   = ipairs, setmetatable, pcall, type
local cjson                 = require "cjson.safe"
local resty_sha256          = require "resty.sha256"
local str                   = require "resty.string"
local gw_conf               = require "trustbuilder-gateway.configuration"
local rc                    = require "resty.redis.connector"


local function generatePrincipalDaoError(message)
    ngx.log(ngx.ERR,"Principal failed: " .. message)
    ngx.exit(500)
end

local PrincipalDao = {}
PrincipalDao.__index = PrincipalDao

setmetatable(PrincipalDao, {
    __call = function (cls, ...)
        return cls.new(...)
    end,
})

PrincipalDao.new = function(self, configuration)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.new")
    local conf
    local confErr
    if not configuration then
        conf,confErr = gw_conf:new()
        if not conf then
            ngx.log(ngx.ERR,confErr)
            ngx.exit(500)
        end
    else
        conf = configuration
    end

    self.conf = conf

    return self
end

PrincipalDao.putConnectionInPool = function(self, redisCon)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.putConnectionInPool")
    local ok, err = redisCon:set_keepalive(self.conf.session_pool_timeout, self.conf.session_pool_size)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
        return nil, nil, err
    else
        ngx.log(ngx.DEBUG, "Status of connection pool update: " .. ok)
    end
end

PrincipalDao.createRedisConnection = function(self)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.createRedisConnection")

    local redisCon, redisErr = rc:connect(self.conf.redis_connection)
    if not redisCon then
        generatePrincipalDaoError("Problem Connecting to redis: " .. redisErr)
    else
        ngx.log(ngx.NOTICE, "Connection used: " .. redisCon:get_reused_times())
    end
    return redisCon
end


PrincipalDao.save = function(self, userSession, credentialIndex, ttl)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.save")

    local sha256 = resty_sha256:new()
    local rc = self:createRedisConnection()
    local userSessionId

    if not userSession.principal then
        return nil, "Missing Principal ID (.principal [STRING])"
    end

    if not userSession.meta then
        return nil, "Missing Meta information (.meta [OBJECT])"
    end

    if not userSession.meta.auth_time then
        return nil, "Missing Auth Time meta information (.meta.auth_time [INT])"
    end

    if not credentialIndex then
        sha256:update(userSession.principal .. "." .. userSession.meta.auth_time)
        local digest = sha256:final()
        userSessionId = str.to_hex(digest)
    else
        userSessionId = credentialIndex
    end

    cjson.encode_empty_table_as_object(false)
    local redis_value = cjson.encode(userSession)
    local redisSetPrincipal, redisSetPrincipalErr = rc:set("CRED:" .. userSessionId, redis_value)
    if not redisSetPrincipal then
        self:putConnectionInPool(rc)
        return nil, "Error setting key in redis: " .. redisSetPrincipalErr
    end

    local redisSetPrincipalTtl,redisSetPrincipalTtlErr = rc:expire("CRED:"..userSessionId,ttl)
    self:putConnectionInPool(rc)
    if not redisSetPrincipalTtl then
        return nil, "Error setting expire on credential in redis: " .. redisSetPrincipalTtlErr
    end

    return userSessionId
end

PrincipalDao.get = function(self, sessionId)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.get")

    local rc = self:createRedisConnection()
    local credential = rc:get("CRED:" .. sessionId)
    self:putConnectionInPool(rc)

    if not credential or credential == ngx.null then
        return nil, "PRINCIPALNOTFOUND"
    end

    local cred, err = cjson.decode(credential)
    if not cred then
        -- ngx.log(ngx.ERR,"Decode session failed: " .. err)
        return nil, err
    end

    return cred
end

PrincipalDao.delete = function(self, sessionId)
    ngx.log(ngx.DEBUG, ">>>> PrincipalDao.delete")
    local rc = self:createRedisConnection()
    local ok,err = rc:del("CRED:" .. sessionId)
    self:putConnectionInPool(rc)
    if not ok then
        return nil, err
    end

    return ok
end

return PrincipalDao


