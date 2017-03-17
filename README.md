Name
====

gateway - A Policy Enforcment Point written in lua with support of session cookies or api based requests

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Authentication](#authentication)
* [Authorization](#authorization)

Status
======

This library is considered experimental and still under active development.

The API is still in flux and may change without notice.

Description
===========

This library requires Openresty adn redis and following modules: 

* [lua-resty-redis-connector](https://github.com/pintsized/lua-resty-redis-connector)
* [lua-resty-cookie](https://github.com/cloudflare/lua-resty-cookie)

Synopsis
========

``` server {
      
	# Standard nginx configuration

	# Begin variable configuration
	set $session_store_location         '127.0.0.1:6379';
	set $session_timeout                '600';
	set $session_inactivity_timeout     '300';
	set $session_cookie                 'MY_SESSION_COOKIE';

	set $session_auth                   'foobared';
	set $login_url                      '/idhub/gw-login';
	set $authorization_url              '/authzServer';
	set $authorization_cache_time       '60';



	#Location configurations

	#Authentication Interface Example
    location /auth {
        header_filter_by_lua_block {
          require("trustbuilder-gateway.auth_interface")()
        }
        
        content_by_lua_block {
          local b64session,err = ngx.encode_base64('{"principal":"Username", "meta":{"auth_time":"1460382419000"} ,"attributes":{"email":"user@example.net"}}')
          ngx.header["X-TB-AUTH"] = b64session
          ngx.say("AUTH")
        }
    }

    location = /t {
	    access_by_lua_block {
	    	--- Send credential username to backend
	    	local header_map = {
            	my_username = "credential.principal",
            	my_email = "credential.attributes['email']"
        	}
	      	require("trustbuilder-gateway.protect").web_app(header_map)
	    }
	    content_by_lua_block {
	      	ngx.say("HIT")
	    }
	}

	location = /api {
		access_by_lua_block {
	    	--- Send credential username to backend
	    	local header_map = {
            	my_username = "credential.principal",
            	my_email = "credential.attributes['email']"
        	}
	      	require("trustbuilder-gateway.protect").api(header_map)
	    }
	}

	# Authorization Header
    location = /authzServer {
	  	internal;
	  	proxy_pass http://127.0.0.1:$server_port/authorizationController;
	}

	location = /authorizationController {
		content_by_lua_block {
			--- Allow
		    ngx.header["X-TB-AZN"] = '{"score":1}'
		    --- Deny
		    --- ngx.header["X-TB-AZN"] = '{"score":0, "reason": "Deny"}'
		    ngx.exit(200)
	  	}
	}

  }

```
[Back to TOC](#table-of-contents)

Authentication
==============

To authenticate a user in the gateway it is sufficient to put a Response header X-TB-AUTH with a base64encoded JSON.

Example

```{
    "meta": {
        "created": 1448283712000,
        "auth_time": 1461853344933,
        "updated": 1458906917000
    },
    "attributes": {
        "nickname": "User",
        "groups": [
            "Admin",
            "Engineer"
        ],
        "locale": "nl-BE",
        "website": "http://www.securit.biz",
        "isAdministrator": "yes"
    },
    "principal": "MyUsername"
}
```
[Back to TOC](#table-of-contents)


Authorization
=============

To authorize the user you have all the user information and location and method available. As a response you are expected to send a json with a score. 0 to fail 1 to allow
[Back to TOC](#table-of-contents)


