# Built-in template sources

The matcher strings in `templates.json` are short observable signatures used to identify public diagnostic surfaces. The pack does not contain third-party executable code or downloaded vulnerability templates.

- Go pprof index: [Go net/http/pprof source](https://go.dev/src/net/http/pprof/pprof.go). The check requests only `/debug/pprof/`, not profiling data or traces.
- Spring Actuator mappings: [Spring Boot Actuator endpoint reference](https://docs.spring.io/spring-boot/4.0/reference/actuator/endpoints.html) and [mappings response schema](https://docs.spring.io/spring-boot/api/rest/actuator/mappings.html). The check reports the endpoint as an information exposure indicator; whether it is acceptable depends on the deployment's access policy.
- Django debug 404: [Django technical 404 template](https://github.com/django/django/blob/main/django/views/templates/technical_404.html). The check requests one deliberately missing path and looks for the technical page plus the `DEBUG = True` marker.
- Public OpenAPI specifications: [OpenAPI Specification](https://spec.openapis.org/oas/latest.html) and [springdoc-openapi](https://springdoc.org/). The checks request only the fixed `/openapi.json` and `/v3/api-docs` paths, require JSON content and OpenAPI markers, and report availability as informational. Response schemas are not copied into the report.
- Git repository configuration: [Git repository layout](https://git-scm.com/docs/gitrepository-layout). The check requests only `/.git/config`, requires Git configuration markers, and never copies repository configuration values into the report.
- PHP configuration information: [PHP `phpinfo()` manual](https://www.php.net/manual/en/function.phpinfo.php). The check requests only `/phpinfo.php` and requires the `phpinfo()` page and PHP version markers; response contents are not copied into the report.
- Apache server status: [Apache `mod_status` documentation](https://httpd.apache.org/docs/2.4/mod/mod_status.html). The check requests only `/server-status` and matches the documented status-page markers; response contents are not copied into the report.
- Go expvar: [Go `expvar` package](https://pkg.go.dev/expvar). The check requests only `/debug/vars`, requires the standard `cmdline` and `memstats` JSON entries, and does not copy process arguments or metrics into the report.

These rules are narrow indicators, not a general CVE database. Confirm a finding against the target's intended configuration before remediation.
