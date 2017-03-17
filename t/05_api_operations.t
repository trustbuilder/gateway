use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

no_shuffle();

run_tests();

__DATA__

=== API Call defaultCacheKey score 0, no reason
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":0}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
403

=== API Call defaultCacheKey score 0, no reason, other authorization controller
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2({
        authzLocation = "/myAuthzTest"
      })
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}

location = /authzServer {
  internal;
  proxy_pass http://127.0.0.1:$server_port/authorizationController;
}

location = /myAuthzTest {
  internal;
  proxy_pass http://127.0.0.1:$server_port/blah;
}

location = /blah {

  content_by_lua_block {
    ngx.log(ngx.DEBUG, ngx.req.raw_header(true))
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-URI"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-AUTH-LOC"])
    ngx.log(ngx.DEBUG, ngx.req.get_headers()["X-TB-SESSION"])

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":0}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
403

=== API Call defaultCacheKey score 0, reason: invalid token
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":0, "reason":"invalid_token"}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
401

=== API Call defaultCacheKey score 0, reason: insufficient_scope
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":0, "reason":"insufficient_scope"}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
403

=== API Call defaultCacheKey score 0, reason: invalid_request
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":0, "reason":"invalid_request"}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
400

=== API Call defaultCacheKey missing AZN Result
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'true';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    -- ngx.say('{"score":0, "reason":"invalid_request"}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request
GET /t
--- error_code eval
403

=== API Call defaultCacheKey caching test X-TB-AZN
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.header["X-TB-AZN"] = '{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}'
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT"
]

=== API Call defaultCacheKey caching test aznInHeaders in location config
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2({
        aznInHeaders = "false"
      })
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT"
]


=== API Call defaultCacheKey caching test
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT"
]


=== API Call defaultCacheKey caching test
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234

--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT"
]


=== API Call defaultCacheKey caching test, no headers
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}


--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEKEY",
"x-tb-azn-cache: NOCACHEKEY"
]

=== API Call defaultCacheKey caching test,  cache ttl check
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2()
    }
    echo_sleep 2;
    echo ok;
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 3, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
Authorization: Bearer 1234
--- request eval
["GET /t", "GET /t", "GET /t"]
--- error_code eval
[200,200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT",
"x-tb-azn-cache: NOCACHEHIT",
]

=== API Call customCacheKeyheader caching test
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2({
        cacheKeyHeader = "test"
      })
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
test: Bearer

--- request eval
["GET /t", "GET /t"]
--- error_code eval
[200,200]
--- response_headers eval
[
"x-tb-azn-cache: NOCACHEHIT",
"x-tb-azn-cache: CACHEHIT"
]

=== API Call customCacheKeyheader Backend headers set
--- http_config eval: $::HttpConfig
--- config

set $authorization_url "/authzServer";
set $session_timeout 10;
set $azn_in_headers 'false';

location = /t {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").api_v2({
        headers = {
            x_tb_subject = 'credential.attributes["idp|up_subject"]'
        },
        cacheKeyHeader = "test"
      })
    }
    content_by_lua_block {
      ngx.say(ngx.req.get_headers()['x-tb-subject'])
      ngx.exit(200)
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

    ngx.req.read_body()
    ngx.log(ngx.DEBUG, ngx.req.get_body_data())
    ngx.say('{"score":1, "cache": 60, "principal": {"principal":"IDHUB_ADMINISTRATOR","attributes":{"idp|up_subject":"Administrator"},"meta":{"created":1484220153000,"updated":1487836987000,"auth_time":1487837091344}}}')
    ngx.exit(200)
  }
}

--- more_headers
test: Bearer

--- request
GET /t
--- error_code: 200

--- response_body
Administrator

