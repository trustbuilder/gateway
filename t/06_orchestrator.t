use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = qq{
    lua_package_path 'libs/?.lua;;';
    lua_shared_dict               aznCache 10m;
    lua_shared_dict               authCache 50m;
};

no_shuffle();

run_tests();

__DATA__

=== Orchestrator Admin Redirect to login, set session cookie, params, admin api enabled
--- http_config eval: $::HttpConfig
--- config
set $idhub_install_enabled          'true'; #In production this is a wise choice
set $idhub_admin_enabled            'true';
set $idhub_admin_api_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin", "GET /idhub/admin/bar"]
--- error_code eval
[303,303]
--- error_log
Admin call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin, admin false, 403
--- http_config eval: $::HttpConfig
--- config
set $idhub_install_enabled          'true'; #In production this is a wise choice
set $idhub_admin_enabled            'false';
set $idhub_admin_api_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin", "GET /idhub/admin/bar"]
--- error_code eval
[403,403]
--- error_log
Admin call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin, admin api false, 403
--- http_config eval: $::HttpConfig
--- config
set $idhub_install_enabled          'true'; #In production this is a wise choice
set $idhub_admin_enabled            'false';
set $idhub_admin_api_enabled        'false';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin/api", "GET /idhub/admin/api/v1"]
--- error_code eval
[403,403]
--- error_log
Admin API call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin, admin api true, admin false, 403
--- http_config eval: $::HttpConfig
--- config
set $idhub_install_enabled          'true'; #In production this is a wise choice
set $idhub_admin_enabled            'false';
set $idhub_admin_api_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin/api", "GET /idhub/admin/api/v1"]
--- error_code eval
[403,403]
--- error_log
Admin API call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin, admin api true, 303
--- http_config eval: $::HttpConfig
--- config
set $idhub_install_enabled          'true'; #In production this is a wise choice
set $idhub_admin_enabled            'true';
set $idhub_admin_api_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin/api", "GET /idhub/admin/api/v1"]
--- error_code eval
[303,303]
--- error_log
Admin API call
--- no_error_log
[warn]
[error]

=== Orchestrator SelfService Redirect to login, set session cookie, params
--- http_config eval: $::HttpConfig
--- config
location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/selfservice", "GET /idhub/selfservice/bar"]
--- error_code eval
[303,303]
--- error_log
SelfService call
--- no_error_log
[warn]
[error]

=== Orchestrator Public
--- http_config eval: $::HttpConfig
--- config
location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/gw-login", "GET /idhub/saml2/sso"]
--- error_code eval
[200,200]
--- error_log
Public call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin API, with XMLHttpRequest
--- http_config eval: $::HttpConfig
--- config
set $idhub_admin_api_enabled        'true';
set $idhub_admin_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- more_headers
X-Requested-With: XMLHttpRequest

--- request eval
["GET /idhub/admin/api/v1/principal", "GET /idhub/admin/api"]
--- error_code eval
[409,409]
--- error_log
Admin API call
--- no_error_log
[warn]
[error]

=== Orchestrator Admin API, without XMLHttpRequest
--- http_config eval: $::HttpConfig
--- config
set $idhub_admin_api_enabled        'true';
set $idhub_admin_enabled        'true';

location /idhub {
    access_by_lua_block {
      require("trustbuilder-gateway.protect").orchestrator()
    }
    content_by_lua_block {
      ngx.say("HIT")
    }
}
--- request eval
["GET /idhub/admin/api/v1/principal", "GET /idhub/admin/api"]
--- error_code eval
[303,303]
--- error_log
Admin API call
--- no_error_log
[warn]
[error]