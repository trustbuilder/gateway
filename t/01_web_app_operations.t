use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

no_shuffle();

run_tests();

__DATA__

=== Redirect to login, set session cookie, no params
--- http_config eval: $::HttpConfig
--- config

set $credential_fallback_salt_session_cookie true;

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
Set-Cookie: tb=.*
--- error_code: 303


=== Redirect to login, set session cookie, params
--- http_config eval: $::HttpConfig
--- config
set $credential_fallback_salt_session_cookie true;

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request
GET /t?qp1=foo&qp2=bar
--- error_code: 303
--- response_headers_like
Location: /idhub/gw-login\?operation=login&ref=%2Ft%3Fqp1%3Dfoo%26qp2%3Dbar
Set-Cookie: tb=.*



=== Login call with header
--- http_config eval: $::HttpConfig
--- config
set $credential_fallback_salt_session_cookie true;

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
--- more_headers
Cookie: tb=FOOBAR; 
--- error_code: 303
--- response_headers_like
Location: /idhub/gw-login\?operation=login&ref=%2Ft


=== Web app authentication (create cookie header)
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";
set $credential_fallback_salt_session_cookie true;
set $session_timeout '5';
set $session_inactivity_timeout '5';

location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.header["X-TB-AZN"] = '{"score":1, "error": 0}'
    ngx.exit(200)
  }
}
--- request
GET /auth
--- more_headers
Cookie: tb=01_WEB_APP_ALLOW;
--- error_code chomp
200

--- response_body
AUTH

--- response_headers
Set-Cookie: X-TB-CREDENTIAL=_-wfQRdD8EOX_UnyNbxciGMoY3stISh03f3MYhtHDh1R9VuFCWboDEK8aigk4U2NssWLu-Jsf1QLL3qglEex6DX0B27AqWecNzj3QKTtMtYD2P8R-LkWdV2ORCyMgkRf5LoUBH0kRQOPDllCJQbNZm156LmbZ3zT1Fv0e4BbZbkAwPuwTvnMspNij2fgNHv_jSasIgE7N9GiTHzaOEr1DTT9NHbnBu_KazEM01qeYEInYBYVzU_ONzMQjKRXYZle54pWwC68frlPmLWhv1BiWA..; Path=/; Secure; HttpOnly

--- no_error_log
[error]


=== Web app authentication (Redis Input)
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";


location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.header["X-TB-AZN"] = '{"score":1, "error": 0}'
    ngx.exit(200)
  }
}
--- request
GET /t
--- more_headers
Cookie: tb=01_WEB_APP_ALLOW;X-TB-CREDENTIAL=_-wfQRdD8EOX_UnyNbxciGMoY3stISh03f3MYhtHDh1R9VuFCWboDEK8aigk4U2NssWLu-Jsf1QLL3qglEex6DX0B27AqWecNzj3QKTtMtYD2P8R-LkWdV2ORCyMgkRf5LoUBH0kRQOPDllCJQbNZm156LmbZ3zT1Fv0e4BbZbkAwPuwTvnMspNij2fgNHv_jSasIgE7N9GiTHzaOEr1DTT9NHbnBu_KazEM01qeYEInYBYVzU_ONzMQjKRXYZle54pWwC68frlPmLWhv1BiWA..;

--- error_code chomp
200

--- response_body
HIT

--- response_headers_like
Set-Cookie: X-TB-CREDENTIAL=; Expires=.*

--- no_error_log
[error]

--- curl
--- ONLY

=== Web app authorization deny no extra vars
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";
set $credential_fallback_salt_session_cookie true;

error_page 303 @error_pages;

location @error_pages {
    internal;
    content_by_lua_block {
        ngx.say('303')
    }
}

location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.header["X-TB-AZN"] = '{"score":0, "reason": "Deny"}'
    ngx.exit(200)
  }
}
--- request eval
["GET /auth", "GET /t"]
--- more_headers
Cookie: tb=01_WEB_APP_DENY1;
--- error_code eval
[200,303]
--- response_body eval
["AUTH\x{0a}", "303\x{0a}"]
--- response_headers eval
[
  "",
  "Location: /idhub/gw-login\?operation=error&ref=%2Ft"
]
--- no_error_log
[error]


=== Web app authorization deny extra vars
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";
set $credential_fallback_salt_session_cookie true;

error_page 303 @error_pages;

location @error_pages {
    internal;
    content_by_lua_block {
        ngx.say('303')
    }
}

location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.header["X-TB-AZN"] = '{"score":0, "reason": "Deny", "info": {"blah":"baaah"}}'
    ngx.exit(200)
  }
}
--- request eval
["GET /auth", "GET /t"]
--- more_headers
Cookie: tb=01_WEB_APP_DENY2;
--- error_code eval
[200,303]
--- response_body eval
["AUTH\x{0a}", "303\x{0a}"]
--- response_headers eval
[
  "",
  "Location: /idhub/gw-login\?operation=error&ref=%2Ft&blah=baaah&reason=Deny"
]
--- no_error_log
[error]


=== Web app authorization stepup
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";
set $credential_fallback_salt_session_cookie true;

error_page 303 @error_pages;

location @error_pages {
    internal;
    content_by_lua_block {
        ngx.say('303')
    }
}

location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.header["X-TB-AZN"] = '{"score":0, "reason": "StepUp", "method":1, "comparison":"minimum"}'
    ngx.exit(200)
  }
}
--- request eval
["GET /auth", "GET /t"]
--- more_headers
Cookie: tb=01_WEB_APP_STEPUP;
--- error_code eval
[200,303]
--- response_body eval
["AUTH\x{0a}", "303\x{0a}"]
--- response_headers eval
[
  "",
  "Location: /idhub/gw-login\?operation=stepup&ref=%2Ft&comparison=minimum&method=1"
]
--- no_error_log
[error]

=== Web app authorization reauthenticate
--- http_config eval: $::HttpConfig
--- config
set $authorization_url "/authzServer";
set $credential_fallback_salt_session_cookie true;

error_page 303 @error_pages;

location @error_pages {
    internal;
    content_by_lua_block {
        ngx.say('303')
    }
}

location /auth {
    header_filter_by_lua_block {
      require("trustbuilder-gateway.auth_interface")()
    }

    content_by_lua_block {
      local b64session,err = ngx.encode_base64('{"principal":"IDHUB_ADMINISTRATOR", "meta":{"auth_time":"1460382419000"} ,"attributes":{"common|email":"gp@trustbuilder.be"}, "authzLocations": ["/t"]}')
      ngx.header["X-TB-AUTH"] = b64session
      ngx.say("AUTH")
    }
}

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /authorizationController {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, "=======")
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["TB_AUTH_URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["TB_AUTH_LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["TB_SESSION"])
    ngx.log(ngx.DEBUG, "=======")

    ngx.header["X-TB-AZN"] = '{"score":0, "reason": "ReAuthenticate", "method":1, "comparison":"minimum"}'
    ngx.exit(200)
  }
}
--- request eval
["GET /auth", "GET /t"]
--- more_headers
Cookie: tb=01_WEB_APP_REAUTHENTICATE;
--- error_code eval
[200,303]
--- response_body eval
["AUTH\x{0a}", "303\x{0a}"]
--- response_headers eval
[
  "",
  "Location: /idhub/gw-login\?operation=reauthenticate&ref=%2Ft"
]
--- no_error_log
[error]



=== Public Web Application, without sessioncookie
--- http_config eval: $::HttpConfig
--- config

set $credential_fallback_salt_session_cookie true;

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").public_web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request
GET /t
--- error_code: 200
--- response_body
HIT

=== Public Web Application, with sessioncookie
--- http_config eval: $::HttpConfig
--- config
set $credential_fallback_salt_session_cookie true;

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").public_web_app()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request
GET /t
--- more_headers
Cookie: tb=01_PROTECTED_LOCATION_5;

--- error_code: 200
--- response_body
HIT



