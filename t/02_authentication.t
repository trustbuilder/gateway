use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};


no_shuffle();

run_tests();

__DATA__

=== TEST 1: Authentication No header set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      -- ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_1"
      ngx.say("OAUTH Authenticate")
    }
}

--- request
GET /auth

--- error_code: 200
--- response_body
OAUTH Authenticate
--- error_log: No matching headers found for authentication

=== TEST 2: Authentication header set, no cookie set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_2"
      ngx.say("OAUTH Authenticate")
    }
}

--- request
GET /auth

--- error_code: 200
--- response_body
OAUTH Authenticate
--- error_log: Save Session in
--- raw_response_headers_unlike: X-TB-AUTH: .*


=== TEST 3: Authentication header set, cookie set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      -- ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      -- ngx.header["X-TB-SESSION"] = "61CAA3D5456195E06D129F5DDF5658F346D5C7889029A4B6DE112EAF1568599B04712A73F4A6EAA1FAC9D3E4C84B65CB54BFEA2E3683321511EB94BE917A64C7"
      ngx.say("OAUTH Authenticate")
    }
}

location /t {
    content_by_lua_block {
      local ck = require "resty.cookie"
      local cookie, cookie_err = ck:new()   
      local session_cookie = ngx.var.session_cookie or 'tb'
  
      local cookievalue = cookie:get(session_cookie)
      
      local gw_session = require("trustbuilder-gateway.session")
      
      local index, user_session = gw_session:retrieve(cookievalue)
      
      ngx.say(user_session.principal)
  
    }
}

--- request eval
["GET /auth", "GET /t"]
--- more_headers 
Cookie: tb=02_AUTHENTICATION_3
--- response_body eval
["OAUTH Authenticate\x{0a}","IDHUB_ADMINISTRATOR\x{0a}"]
--- no_error_log
[error]

=== TEST 4: Authentication header set, session header set, cookie not set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-CREDENTIAL_TTL"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_4"
      ngx.say("OAUTH Authenticate")
    }
}

location /t {
    content_by_lua_block {
      local ck = require "resty.cookie"
      local cookie, cookie_err = ck:new()   
      local session_cookie = ngx.var.session_cookie or 'tb'
  
      local cookievalue = cookie:get(session_cookie)
      
      local gw_session = require("trustbuilder-gateway.session")
      
      
      local index, user_session = gw_session:retrieve("02_AUTHENTICATION_4")
      
      ngx.say(user_session.principal)
  
    }
}

--- request eval
["GET /auth", "GET /t"]
--- response_body eval
["OAUTH Authenticate\x{0a}","IDHUB_ADMINISTRATOR\x{0a}"]
--- no_error_log
[error]


=== TEST 5: Authentication header set, session header set, cookie set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_5"
      ngx.say("OAUTH Authenticate")
    }
}

location /t {
    content_by_lua_block {
      local ck = require "resty.cookie"
      local cookie, cookie_err = ck:new()   
      local session_cookie = ngx.var.session_cookie or 'tb'
  
      local cookievalue = cookie:get(session_cookie)
      
      local gw_session = require("trustbuilder-gateway.session")
      
      local index, user_session = gw_session:retrieve("SESSION")
            
      ngx.say(user_session)
      
      index, user_session = gw_session:retrieve("02_AUTHENTICATION_5")
      
      ngx.say(user_session.principal)
  
    }
}

--- request eval
["GET /auth", "GET /t"]
--- more_headers
Cookie: tb=SESSION
--- response_body eval
["OAUTH Authenticate\x{0a}","nil\x{0a}IDHUB_ADMINISTRATOR\x{0a}"]
--- no_error_log
[error]


=== TEST 6: Malformed JSON (no principal)
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      -- ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_6"
      ngx.say("OAUTH Authenticate")
    }
}

--- request
GET /auth
--- response_body
OAUTH Authenticate
--- error_log: IGNORING X-TB-AUTH header, malformed
--- error_code: 200


=== TEST 7: Malformed JSON (incorrect base64)
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "1"
      ngx.header["X-TB-AUTH"] = "foobar"
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_7"
      ngx.say("OAUTH Authenticate")
    }
}

--- request
GET /auth
--- response_body
OAUTH Authenticate
--- error_log: IGNORING X-TB-AUTH header, malformed
--- error_code: 200


=== TEST 8: Malformed JSON (invalid json)
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('"meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "1"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_8"
      ngx.say("OAUTH Authenticate")
    }
}

--- request
GET /auth
--- response_body
OAUTH Authenticate
--- error_log: IGNORING X-TB-AUTH header, malformed
--- error_code: 200

=== TEST 9: Test Logout
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR","meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_09"
      ngx.say("OAUTH Authenticate")
    }
}

location /logout {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
       ngx.header["X-TB-LOGOUT"] = "01205b5c780da66fea872495ba796d1af28604f5196b8adca207e870690bfa6f"
       ngx.say("LOGOUT")
    }
}

location = /t {
  access_by_lua_block {
    require("trustbuilder-gateway.protect").api()
  }
  content_by_lua_block {
    ngx.say("HIT")
  }
}

--- more_headers
Authorization: Bearer 02_AUTHENTICATION_09

--- request eval
["GET /auth", "GET /t", "GET /logout", "GET /t"]
--- response_body eval
["OAUTH Authenticate\x{0a}", "HIT\x{0a}", "LOGOUT\x{0a}", "<html>\x{0d}\x{0a}<head><title>401 Authorization Required</title></head>\x{0d}\x{0a}<body bgcolor=\"white\">\x{0d}\x{0a}<center><h1>401 Authorization Required</h1></center>\x{0d}\x{0a}<hr><center>openresty/1.11.2.2</center>\x{0d}\x{0a}</body>\x{0d}\x{0a}</html>\x{0d}\x{0a}"]

--- error_code eval
[200,200,200,401]

--- no_error_log
[error]

=== TEST 10: Authentication header set, session header set, scopes set
--- http_config eval: $::HttpConfig
--- config
location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }
    
    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}}')
      ngx.header["X-TB-EXPIRES_IN"] = "5"
      ngx.header["X-TB-CREDENTIAL_TTL"] = "5"
      ngx.header["X-TB-AUTH"] = b64session
      ngx.header["X-TB-SESSION"] = "02_AUTHENTICATION_9"
      ngx.header["X-TB-OAUTH-SCOPES"] = "scope1 scope2 scope3"
      ngx.say("OAUTH Authenticate")
    }
}

location /t {
    content_by_lua_block {
      local ck = require "resty.cookie"
      local cookie, cookie_err = ck:new()   
      local session_cookie = ngx.var.session_cookie or 'tb'
  
      local cookievalue = cookie:get(session_cookie)
      
      local gw_session = require("trustbuilder-gateway.session")
      
      local index, user_session = gw_session:retrieve("02_AUTHENTICATION_9")
      local scopes = gw_session:get_scopes("02_AUTHENTICATION_9")
      
      ngx.say(user_session.principal)
      ngx.say(scopes)
    }
}

--- request eval
["GET /auth", "GET /t"]
--- response_body eval
["OAUTH Authenticate\x{0a}","IDHUB_ADMINISTRATOR\x{0a}scope1 scope2 scope3\x{0a}"]
--- no_error_log
[error]