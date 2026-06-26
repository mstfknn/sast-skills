# Express profile

Facts a detection skill should apply during verify to avoid false positives on Express's safe defaults.

## Safe by default (false-positive killers)

- **SQL injection / query parameterization** — Express has no ORM or query layer; safety depends entirely on the DB driver. `pg` (node-postgres) parameterizes with `pool.query('SELECT ... WHERE id = $1', [id])`; `mysql2` uses `connection.execute('SELECT ... WHERE id = ?', [id])`; `better-sqlite3` uses `db.prepare('SELECT ... WHERE id = ?').get(id)`. These patterns are safe. Flag any query where the SQL string is assembled with template literals `` `SELECT ... ${userInput}` ``, `+` concatenation, or string interpolation before being passed to the driver.

- **XSS / templating** — Express has no built-in template engine and no default escaping. Escaping behavior is entirely engine-dependent: EJS escapes `<%= %>` but not `<%- %>`; Pug escapes `#{var}` but not `!{var}`; Handlebars escapes `{{var}}` but not `{{{var}}}`. Flag unescaped interpolation variants and `res.send(userInput)` without prior sanitization.

- **Security headers** — Express sets no security-relevant response headers by default. `helmet` must be explicitly added (`app.use(helmet())`). Flag applications where `helmet` (or equivalent manual header setting) is absent from the middleware chain for production routes.

- **CSRF** — Express has no built-in CSRF protection. `csurf` (deprecated but widely used) or `csrf-csrf` must be added explicitly. Flag mutating endpoints (POST/PUT/PATCH/DELETE) that accept `Content-Type: application/x-www-form-urlencoded` or `multipart/form-data` without CSRF middleware; JSON-only APIs using `Authorization` headers and `SameSite` cookies may be exempt.

- **Mass assignment** — `express.json()` and `express.urlencoded()` parse the full request body into a plain object; spreading or directly assigning that object into a model/DB call is the sink. Suppress findings where only explicit named properties are read from `req.body`. Flag `Object.assign(model, req.body)`, spread `{ ...req.body }` into DB inserts/updates, and ORM upsert calls passed `req.body` directly (e.g., `User.create(req.body)`).

- **Auth / session** — `express-session` sets `httpOnly: true` by default but `secure: false`; `cookie.secure` must be set to `true` in production. Flag `secret` set to a hardcoded string, `resave: true` with a non-rolling session store, and `cookie.secure: false` in production configuration.

- **Deserialization** — `express.json()` uses `JSON.parse()`, which is safe. Flag use of `node-serialize` / `serialize-javascript` deserializing untrusted input, and `eval()` / `new Function()` on request data.

- **Secrets / config** — Credentials must come from environment variables via `process.env`. Flag hardcoded API keys, JWT secrets, or DB passwords in source files; flag missing `.env` entries in `.gitignore`.

## Still a real sink (do not suppress)

- `` pool.query(`SELECT ... WHERE id = ${req.params.id}`) `` — template literal SQL
- `res.send(req.body.comment)` or `res.render('page', { data: req.query.input })` without escaping
- `<%- userInput %>` (EJS), `!{userInput}` (Pug), `{{{userInput}}}` (Handlebars)
- `app.use(helmet())` absent from the middleware stack
- POST/PUT/DELETE routes without CSRF middleware when using cookie-based sessions
- `Object.assign(record, req.body)` or `Model.create(req.body)` / `Model.update(req.body, ...)`
- `cookie.secure: false` in production session config
- `eval(req.body.code)` or `new Function(req.body.fn)()`
- Hardcoded `secret` in `express-session` or JWT signing calls
