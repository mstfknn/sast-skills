# FastAPI profile

Facts a detection skill should apply during verify to avoid false positives on FastAPI's safe defaults.

## Safe by default (false-positive killers)

- **Input validation / Pydantic** — FastAPI validates and coerces all request bodies, query parameters, and path parameters through Pydantic models by default. A route that declares `body: UserCreate` (a `BaseModel` subclass) or `q: int` as a parameter is safe — Pydantic rejects malformed input before the handler runs. Flag handlers that bypass model binding: `raw_body = await request.body()`, `data = await request.json()`, or `request.form()` parsed manually without a Pydantic model; also flag `model_validate()` called on unsanitized `dict` from `request.json()` when `model_config = ConfigDict(extra='allow')` is set.

- **SQL injection / SQLAlchemy** — SQLAlchemy ORM (`.filter()`, `.where()`, `.select()` with column comparisons) and Core `select()` with bound parameters are safe. Flag `text()` (SQLAlchemy Core textual SQL) called with an f-string or `%` formatting using user-controlled values: `text(f"SELECT ... WHERE name = '{name}'")`; also flag `engine.execute()` / `connection.execute()` with raw string SQL built from user input.

- **CSRF** — FastAPI has no built-in CSRF protection. JSON APIs authenticated with `Authorization: Bearer` headers and no cookies are not CSRF-vulnerable by design. Flag cookie-based authentication (e.g., `response.set_cookie(...)` storing session tokens) on state-changing endpoints that lack an explicit CSRF double-submit cookie or `Origin`/`Referer` check; Starlette's `SessionMiddleware` alone does not add CSRF protection.

- **Security headers** — FastAPI/Starlette set no security headers by default. `starlette-csrf`, `secure`, or manual middleware must be added. Flag production applications without `X-Content-Type-Options`, `X-Frame-Options`, and CSP headers.

- **Auth / JWT** — FastAPI has no built-in auth; `python-jose` / `PyJWT` are common. Flag `algorithms=["none"]` in JWT decode calls, missing `verify_exp=True` (or absent expiry in token creation), `Depends()` security schemes that catch exceptions and return `None` instead of raising `HTTPException(401)`, and `OAuth2PasswordBearer` without actually validating the token in the dependency.

- **Templating** — Jinja2 (via `Jinja2Templates`) auto-escapes HTML by default when `autoescape=True` is set (which `fastapi.templating.Jinja2Templates` enables). Flag `autoescape=False`, `Markup(user_input)`, and `Environment(autoescape=False)` rendering user data.

- **Deserialization** — `request.json()` calls `json.loads()`, which is safe. Flag `pickle.loads()` on request body bytes and `yaml.load(data)` without `Loader=yaml.SafeLoader`.

- **Secrets / config** — Pydantic Settings (`pydantic-settings`) with `BaseSettings` reads from environment variables. Flag hardcoded secrets in settings classes as default values (e.g., `secret_key: str = "hardcoded"`), `.env` files committed to VCS, and `SECRET_KEY` literals in application code.

## Still a real sink (do not suppress)

- `raw = await request.body(); data = json.loads(raw)` — manual parsing that skips Pydantic validation
- `await request.json()` spread directly into DB calls without a Pydantic model gate
- `text(f"SELECT ... WHERE id = {user_id}")` — f-string in SQLAlchemy `text()`
- `engine.execute("SELECT ... " + user_input)` — string-concatenated raw SQL
- Cookie-session endpoints without CSRF double-submit or `SameSite=Strict` enforcement
- `jwt.decode(token, key, algorithms=["none"])`
- `Jinja2Templates` with `autoescape=False` rendering user-controlled variables
- `pickle.loads(await request.body())`
- `yaml.load(data)` without `Loader=yaml.SafeLoader`
- `secret_key: str = "changeme"` hardcoded in `BaseSettings` subclass
