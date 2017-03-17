
local ok, tbl_new = pcall(require, "table.new")
if not ok then
  tbl_new = function (narr, nrec) return {} end
end

local cjson = require "cjson"
local ck = require "resty.cookie"
local rc = require "resty.redis.connector"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

local _M = {
  _VERSION = '0.0.1',
}
local mt = { __index = _M }


function _M.split(str, sep)
  if sep == nil then
    sep = "%s"
  end
  local t={} ; i=0
  for str in string.gmatch(str, "([^"..sep.."]+)") do
    t[i] = str
    i = i + 1
  end
  return t
end

function _M.starts(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

function _M.ends(String,End)
   return End=='' or string.sub(String,-string.len(End))==End
end

return _M