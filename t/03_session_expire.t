use Test::Nginx::Socket 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

no_shuffle();
run_tests();

__DATA__

=== TEST 1: authentication, cookie set, session not expired
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "WEBAPP"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      local rc = require "resty.redis.connector"
      local conf = require("trustbuilder-gateway.configuration"):new()
      local red,err = rc:connect(conf.redis_connection)
      local expire = red:ttl("SESS:03_SESSION_EXPIRE_01")
      ngx.log(ngx.DEBUG, "key ttl " .. expire)
      if expire > 3598 and expire < 3601 then
        ngx.say("OK")
      end
    }
}

--- more_headers
Cookie: tb=03_SESSION_EXPIRE_01

--- request eval
["GET /auth", "GET /t"]

--- response_body eval
["AUTH\x{0a}","OK\x{0a}"]
--- no_error_log
[error]

=== TEST 2: authentication, API, SESSION EXPIRES IN 2 
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-EXPIRES_IN"] = "2"
      ngx.header["X-TB-SESSION"] = "03_SESSION_EXPIRE_2"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api()
    }
    content_by_lua_block {
      ngx.say("OK")
      ngx.sleep(2)
    }
}

--- more_headers
Authorization: Bearer 03_SESSION_EXPIRE_2

--- request eval
["GET /auth", "GET /t", "GET /t"]

--- error_code eval
[200,200,401]
--- response_body eval
["AUTH\x{0a}", "OK\x{0a}", "<html>\x{0d}\x{0a}<head><title>401 Authorization Required</title></head>\x{0d}\x{0a}<body bgcolor=\"white\">\x{0d}\x{0a}<center><h1>401 Authorization Required</h1></center>\x{0d}\x{0a}<hr><center>openresty/1.11.2.2</center>\x{0d}\x{0a}</body>\x{0d}\x{0a}</html>\x{0d}\x{0a}"]
--- no_error_log
[error]

=== TEST 3: authentication, API, CREDENTIAL EXPIRES IN 2 
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-CREDENTIAL_TTL"] = "2"
      ngx.header["X-TB-SESSION"] = "03_SESSION_EXPIRE_03"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api()
    }
    content_by_lua_block {
      ngx.say("OK")
      ngx.sleep(2)
    }
}

--- more_headers
Authorization: Bearer 03_SESSION_EXPIRE_03

--- request eval
["GET /auth", "GET /t", "GET /t"]

--- error_code eval
[200,200,401]
--- response_body eval
["AUTH\x{0a}", "OK\x{0a}", "<html>\x{0d}\x{0a}<head><title>401 Authorization Required</title></head>\x{0d}\x{0a}<body bgcolor=\"white\">\x{0d}\x{0a}<center><h1>401 Authorization Required</h1></center>\x{0d}\x{0a}<hr><center>openresty/1.11.2.2</center>\x{0d}\x{0a}</body>\x{0d}\x{0a}</html>\x{0d}\x{0a}"]
--- no_error_log
[error]

=== TEST 4: inactivity timeout
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "WEBAPP"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      local ck = require "resty.cookie"
      local cookie, cookie_err = ck:new()   
      local session_cookie = ngx.var.session_cookie or 'tb'
  
      local cookievalue = cookie:get(session_cookie)
      local rc = require "resty.redis.connector"
      local conf = require("trustbuilder-gateway.configuration"):new()
      local red,err = rc:connect(conf.redis_connection)
      local expire = red:ttl("SESS:"..cookievalue)
      if expire > 3598 and expire < 3601 then
        ngx.log(ngx.DEBUG, "OK key ttl " .. expire)
        ngx.say("OK")
      else
        ngx.log(ngx.DEBUG, "NOK key ttl " .. expire)
        ngx.say("NOK")
      end
      ngx.sleep(5)
      ngx.log(ngx.DEBUG, "END key ttl " .. expire)
    }
}

--- more_headers
Cookie: tb=03_SESSION_EXPIRE_04

--- request eval
["GET /auth", "GET /t", "GET /t"]

--- error_code eval
[200,200,200]

--- response_body eval
["AUTH\x{0a}","OK\x{0a}", "OK\x{0a}"]

--- no_error_log
[error]

--- timeout: 15s


=== TEST 5: regenerate session cookie
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "WEBAPP"
      ngx.say("AUTH")
    }
}

location = /t {
    set $session_regenerate 1;
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("OK")
    }
}

--- more_headers
Cookie: tb=03_SESSION_EXPIRE_05

--- request eval
["GET /auth", "GET /t"] 

--- error_code eval
[200,200]

--- response_body eval
["AUTH\x{0a}","OK\x{0a}"]

--- response_headers_like eval
[
".*",
"Set-Cookie: tb=.*"
]

--- no_error_log
[error]


