# Spring profile

Facts a detection skill should apply during verify to avoid false positives on Spring's safe defaults.

## Safe by default (false-positive killers)

- **SQL injection / repositories** — Spring Data JPA repository methods (derived query methods, `@Query` with named/positional parameters `?1` or `:name`) use prepared statements via JPA/Hibernate. Flag `@Query` where the value string is built with Java string concatenation, `String.format()`, or `+` using method parameters; flag `EntityManager.createQuery()` / `createNativeQuery()` with concatenated strings; flag `JdbcTemplate.query(sql, ...)` where `sql` is assembled from user input rather than a constant.

- **XSS / templating** — Thymeleaf escapes all `th:text` and `th:value` expressions by default. Flag `th:utext` (unescaped), inline `[[...]]` vs `[(...)]` (the latter is unescaped), and `Jsoup.clean()` / `HtmlUtils.htmlUnescape()` called on output sent to the browser without re-escaping.

- **CSRF** — Spring Security enables CSRF protection by default for non-idempotent HTTP methods. Flag `.csrf(csrf -> csrf.disable())` (Spring Security 6.x lambda DSL) and the legacy `.csrf().disable()` chain.

- **Mass assignment / model binding** — `@ModelAttribute` binds all request parameters to the model object by default. Flag models bound with `@ModelAttribute` that lack a corresponding `@InitBinder` using `setAllowedFields()` or `setDisallowedFields()`; also flag `DataBinder.setAllowedFields()` with an overly permissive allowlist.

- **Security headers** — Spring Security adds `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Cache-Control`, and `X-XSS-Protection` headers automatically when the `HttpSecurity` chain is active. Flag explicit removal via `.headers(headers -> headers.disable())` or individual disabling of `frameOptions()`, `contentTypeOptions()`, etc.

- **Auth / session** — `@PreAuthorize`, `@Secured`, and `HttpSecurity.authorizeHttpRequests()` are the authorization mechanisms. Flag controller methods on sensitive paths that have no `@PreAuthorize` / `@Secured` annotation and are not covered by a `requestMatcher` rule; flag `permitAll()` on non-public endpoints.

- **Deserialization** — Spring MVC uses Jackson for JSON deserialization; vanilla Jackson with default typing disabled is safe. Flag `ObjectMapper.enableDefaultTyping()` (deprecated) or `activateDefaultTyping()` with `NON_FINAL` / `OBJECT_AND_NON_CONCRETE` polymorphic typing, and Java deserialization via `ObjectInputStream` on untrusted streams.

- **Secrets / config** — `application.properties` / `application.yml` credentials should reference environment variables (`${DB_PASSWORD}`) or Spring Cloud Config / Vault. Flag hardcoded passwords, API keys, or tokens as literal values in committed config files.

## Still a real sink (do not suppress)

- `@Query("SELECT ... WHERE name = '" + param + "'")` — string-concatenated JPQL/SQL in `@Query`
- `entityManager.createNativeQuery("SELECT ... " + userInput)`
- `jdbcTemplate.query("SELECT ... " + userInput, rowMapper)`
- `th:utext="${userInput}"` and `[(${userInput})]` in Thymeleaf templates
- `.csrf(csrf -> csrf.disable())` or `.csrf().disable()` in `SecurityFilterChain`
- `@ModelAttribute` binding without `@InitBinder` / `setAllowedFields()` allowlist on sensitive objects
- `.headers(headers -> headers.disable())`
- `ObjectMapper.activateDefaultTyping(...)` with permissive type handling
- `ObjectInputStream.readObject()` on data from untrusted sources
- Hardcoded credentials in `application.properties` / `application.yml`
