Name
====

The upstream_dynamic module can be modifies the upstream server without need of restarting nginx.

Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Example Configuration](#example configuration)
* [Directives](#directives)
    * [server_resolver](#server_resolver)
    * [http_upstream_conf](#http_upstream_conf)
* [TODO](#todo)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

This module is still under early development and is still experimental.

Example Configuration
====================

```nginx

http {
    resolver 127.0.0.1:5353;

    server {
        listen       8080;
        server_name  localhost;

        location / {
            proxy_pass http://upstest;
        }
    }

    server {
        listen 8081;
        server_name  localhost;
        location /http_upstream_conf/ {
            allow 127.0.0.1;
            deny all;
            http_upstream_conf;
        }
    }

    upstream upstest {
        zone ups_dyn 3m;
        server_resolver;
        server www.test.com:8081;
    }

}

```

[Back to TOC](#table-of-contents)

Directives
==========

server_resolver
---------------
**syntax:** *server_resolver*

**default:** *no*

**context:** *upstream*

Specify this upstream server will be monitors changes of the IP addresses that correspond to a domain name of the server, and automatically modifies the upstream.

In order for this parameter to work, the `resolver` directive must be specified in the http block.

[Back to TOC](#table-of-contents)

http_upstream_conf
------------------
**syntax:** *http_upstream_conf*

**default:** *no*

**context:** *location*

Turns on the REST API is used to modify upstream server in the surrounding location. Access to this location should be limited.

Supported methods:

* list

    list the specified upstream's server.
* add

    add the server to the upstream.
* down

    down the specified upstream's server.

Consider the following example:

```
http://127.0.0.1:8081/http_upstream_conf/list?ups=upstest

http://127.0.0.1:8081/http_upstream_conf/add?ups=upstest&ip=1.1.1.1

http://127.0.0.1:8081/http_upstream_conf/down?ups=upstest&ip=1.1.1.1
```

[Back to TOC](#table-of-contents)

TODO
====

[Back to TOC](#table-of-contents)

Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)


Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2018, by vislee.

All rights reserved.


[Back to TOC](#table-of-contents)

See Also
========
* http://nginx.org/en/docs/http/ngx_http_upstream_module.html#server
* http://nginx.org/en/docs/http/ngx_http_api_module.html#http_upstreams_http_upstream_name_

[Back to TOC](#table-of-contents)