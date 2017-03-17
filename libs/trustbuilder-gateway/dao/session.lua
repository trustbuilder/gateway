--
-- Created by IntelliJ IDEA.
-- User: gerry
-- Date: 24/02/2017
-- Time: 11:10
-- To change this template use File | Settings | File Templates.
--

local setmetatable                      = setmetatable
local pairs                             = pairs
local ngx                               = ngx
local gw_conf                           = require "trustbuilder-gateway.configuration"
local rc                                = require "resty.redis.connector"
local PrincipalDao                      = require "trustbuilder-gateway.dao.principal"
local random                            = require "trustbuilder-gateway.helpers.random"


local function generateSessionDaoError(message)
    ngx.log(ngx.ERR,"Session failed: " .. message)
    ngx.exit(500)
end

local function tbl_len(T)
    local count = 0
    for _ in pairs(T) do count = count + 1 end
    return count
end

local SessionDao = {}
SessionDao.__index = SessionDao

setmetatable(PrincipalDao, {
    __call = function (cls, ...)
        return cls.new(...)
    end,
})

SessionDao.new = function(self, configuration)
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

SessionDao.putConnectionInPool = function(self, redisCon)
    local ok, err = redisCon:set_keepalive(self.conf.session_pool_timeout, self.conf.session_pool_size)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
        return nil, err
    else
        ngx.log(ngx.DEBUG, "Status of connection pool update: " .. ok)
    end
end

SessionDao.createRedisConnection = function(self)
    local redisCon, redisErr = rc:connect(self.conf.redis_connection)
    if not redisCon then
        generateSessionDaoError("Problem Connecting to redis: " .. redisErr)
    else
        ngx.log(ngx.NOTICE, "Connection used: " .. redisCon:get_reused_times())
    end
    return redisCon
end

SessionDao.get = function(self, sessionId)
    local red = self:createRedisConnection()

    local sess, err = red:hgetall("SESS:" .. sessionId)
    if err then
        self:putConnectionInPool(red)
        return nil,err
    end


    local hashMap = red:array_to_hash(sess)

    if tbl_len(hashMap) == 0 then
        --- ngx.log(ngx.DEBUG,"SESSION_EXPIRED: Session Not found in redis")
        return nil, "SESSION_EXPIRED"
    end

    local credentialIndex = hashMap.credentialindex

    if not credentialIndex then
        ngx.log(ngx.DEBUG,"SESSION_EXPIRED: No Credential Index found")
        --- Incorrect session so removing the session from redis
        self:delete(sessionId)
        return nil, "MALFORMED_SESSION"
    end


    local session_expire = tonumber(hashMap.session_ttl)
    if session_expire > 0 then
        red:expire("SESS:"..sessionId, session_expire)
        self:putConnectionInPool(red)
        ngx.log(ngx.DEBUG,"Refresh inactivity timeout")
    end


    return hashMap
end

SessionDao.delete = function(self,sessionId)
    local red = self:createRedisConnection()

    local ok,err = red:del("SESS:"..sessionId)
    self:putConnectioninPool(red)
    if not ok then
        generateSessionDaoError("Redis Error:" .. err)
    end

    return true
end

SessionDao.save = function(self, sessionId, data)
    local red = self:createRedisConnection()

    local redisKey = "SESS:" .. sessionId

    local session_hash = {
        credentialindex = data.credentialIndex,
        session_ttl = tonumber(data.sessionTtl),
        jwttokencache = "{}",
        authzIndex = random.token(64)
    }

    local okSet,errSet = red:hmset(redisKey,session_hash)
    if not okSet then
        self:putConnectionInPool(red)
        return nil, "Error saving session in redis: " .. errSet
    end

    local okExpire,errExpire = red:expire(redisKey,data.sessionTtl)
    if not okExpire then
        self:putConnectionInPool(red)
        return nil, "Error saving session in redis: " .. errExpire
    end

    self:putConnectionInPool(red)
    return session_hash
end

return SessionDao