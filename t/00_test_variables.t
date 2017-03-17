use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

 
no_shuffle();

run_tests();

__DATA__

=== TEST 1: set loginurl

--- http_config eval: $::HttpConfig
--- config
set $login_url '/foo/bar';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request
GET /t
--- response_headers_like
Location: /foo/bar\?operation=login&ref=%2Ft
Set-Cookie: tb=.*
--- error_code: 303

=== TEST 2: set cookie
--- http_config eval: $::HttpConfig
--- config
set $session_cookie 'foobar';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request
GET /t
--- response_headers_like
Location: /idhub/gw-login\?operation=login&ref=%2Ft
Set-Cookie: foobar=.*
--- error_code: 303
