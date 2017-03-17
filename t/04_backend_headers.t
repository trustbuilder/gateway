use Test::Nginx::Socket 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

no_shuffle();
run_tests();

__DATA__

=== TEST 1: SET COMMON HEADERS 
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
      ngx.header["X-TB-SESSION"] = "04_BACKEND_HEADERS_1"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api()
    }
    content_by_lua_block {
      ngx.say(ngx.req.get_headers()["tb-user"])
      ngx.say(ngx.req.get_headers()["x-tb-session"])
      ngx.say(ngx.req.get_headers()["x-tb-credentialindex"])
      
    }
}

--- more_headers
Authorization: Bearer 04_BACKEND_HEADERS_1

--- request eval
["GET /auth", "GET /t"]

--- error_code eval
[200,200]
--- response_body eval
["AUTH\x{0a}", "IDHUB_ADMINISTRATOR\x{0a}eyJhdHRyaWJ1dGVzIjp7ImNvbW1vbnxlbWFpbCI6ImdwQHRydXN0YnVpbGRlci5iZSJ9LCJtZXRhIjp7ImF1dGhfdGltZSI6IjE0NjAzODI0MTkwMDAifSwicHJpbmNpcGFsIjoiSURIVUJfQURNSU5JU1RSQVRPUiJ9\x{0a}01205b5c780da66fea872495ba796d1af28604f5196b8adca207e870690bfa6f\x{0a}"]
--- no_error_log
[error]

=== TEST 2: SET CUSTOM HEADER
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
      ngx.header["X-TB-SESSION"] = "04_BACKEND_HEADERS_2"
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      local headers = {
        x_header_email = "credential.attributes['common|email']"
      }
      
      require("trustbuilder-gateway.protect").api(headers)
    }
    content_by_lua_block {
      ngx.log(ngx.DEBUG, ngx.req.get_headers()["x-header-email"])
      ngx.say(ngx.req.get_headers()["x-header-email"])
      
    }
}

--- more_headers
Authorization: Bearer 04_BACKEND_HEADERS_2

--- request eval
["GET /auth", "GET /t"]

--- error_code eval
[200,200]
--- response_body eval
["AUTH\x{0a}", "gp\@trustbuilder.be\x{0a}"]

--- no_error_log
[error]
