# Django profile

Facts a detection skill should apply during verify to avoid false positives on Django's safe defaults.

## Safe by default (false-positive killers)

- **SQL injection / ORM** — Django ORM (`.filter()`, `.get()`, `.exclude()`, `.annotate()`, etc.) always parameterizes queries via DB-API 2.0. Flag only `.raw()`, `.extra()`, `RawSQL()`, and `cursor.execute()` / `cursor.executemany()` where the SQL string is built with f-strings, `%` formatting, or `str` concatenation using user-controlled values.

- **XSS / templating** — Django template engine auto-escapes all variables by default. Flag only `{{ value|safe }}`, `mark_safe()`, `format_html()` called with unsanitized user input, and any `{% autoescape off %}` block.

- **CSRF** — `django.middleware.csrf.CsrfViewMiddleware` is enabled in `MIDDLEWARE` by default; every mutating view is protected. Flag `@csrf_exempt`, `csrf_exempt()` wrappers, and deliberate removal of the middleware from `MIDDLEWARE`.

- **Mass assignment** — `ModelForm` with `fields='__all__'` or a missing `fields` / `exclude` declaration exposes every model field to user input. Suppress findings on `ModelForm` that explicitly lists `fields = [...]` as an allowlist; flag `fields = '__all__'` and missing `Meta.fields`.

- **Security headers** — `SECURE_BROWSER_XSS_FILTER`, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT` are opt-in. Flag any production settings file where these are `False` or absent.

- **Auth / session** — `django.contrib.auth` provides password hashing (PBKDF2 by default), `@login_required`, and permission decorators. Flag custom authentication backends that skip `check_password()`, views without `@login_required` / `PermissionRequiredMixin` on sensitive resources, and `SESSION_COOKIE_HTTPONLY = False`.

- **Deserialization** — Django does not deserialize untrusted pickle data in core flows. Flag direct use of `pickle.loads()` on request data, and `django.core.signing` with a weak or hardcoded `SECRET_KEY`.

- **Secrets / config** — `SECRET_KEY` must not be hardcoded in committed settings files; use environment variables or `django-environ` / `python-decouple`. Flag literal `SECRET_KEY = 'hardcoded...'` in any committed settings module.

## Still a real sink (do not suppress)

- `.raw(sql, params=None)` with f-string or concatenated `sql` argument (params list is safe, string concat is not)
- `.extra(where=["user_input"])` or `RawSQL("... %s" % user_input, [])`
- `cursor.execute(f"SELECT ... {user_input}")` — any format besides `cursor.execute(sql, [params])`
- `mark_safe(user_controlled)` and `format_html(template, *args)` where `template` itself is user-controlled
- `{% autoescape off %}` blocks rendering user data
- `@csrf_exempt` on any state-changing view
- `ModelForm.Meta.fields = '__all__'` or no `fields`/`exclude` set
- `DEBUG = True` in production settings
- Hardcoded `SECRET_KEY` in committed code
