# Rails profile

Facts a detection skill should apply during verify to avoid false positives on Rails's safe defaults.

## Safe by default (false-positive killers)

- **SQL injection / ActiveRecord** — ActiveRecord parameterizes all standard query methods: `where(name: value)`, `where("name = ?", value)`, `find(id)`, `find_by(email: value)`. Flag string-interpolated conditions: `where("name = '#{params[:name]}'")`; `find_by_sql("SELECT ... #{user_input}")`; `.order(params[:sort])` without an allowlist; `Arel.sql(user_input)` used directly in query methods.

- **XSS / ERB** — ERB auto-escapes all `<%= %>` output via `CGI.escapeHTML`. Flag `<%= raw(user_input) %>`, `<%= user_input.html_safe %>`, `content_tag` / `link_to` receiving unsanitized user strings with `html_safe` appended, and `render html: user_input` without sanitization.

- **CSRF** — `ActionController::Base` includes `protect_from_forgery with: :exception` by default (Rails 5+). Flag `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` used broadly, and API controllers that inherit from `ActionController::Base` instead of `ActionController::API` while still setting cookies.

- **Mass assignment / strong params** — `ActionController::StrongParameters` requires explicit `params.require(:model).permit(:field1, :field2)`. Flag `params.permit!` (allows all), `params[:model_attrs]` passed directly to `.create()` / `.update()` / `.assign_attributes()` without `.permit()`, and `before_action` that merges `params` without filtering.

- **Security headers** — Rails sets `X-Content-Type-Options: nosniff` and `X-XSS-Protection` headers by default; `Content-Security-Policy` and `Strict-Transport-Security` require `config/initializers/content_security_policy.rb` and `config.force_ssl = true`. Flag production environments without `config.force_ssl = true` and absent CSP configuration.

- **Auth / session** — `has_secure_password` uses bcrypt. `session` is cookie-signed with `secret_key_base`. Flag `secret_key_base` hardcoded in `config/secrets.yml` committed to VCS, missing `config.session_store :cookie_store, secure: true` in production, and authentication checks (`before_action :authenticate_user!` or equivalent) absent on sensitive controllers.

- **Deserialization** — Rails 7+ defaults to JSON for cookie serialization (`config.action_dispatch.cookies_serializer = :json`). Flag `config.action_dispatch.cookies_serializer = :marshal` (enables Ruby marshal deserialization of user-controlled cookies) and direct `Marshal.load` on request data.

- **Secrets / config** — `config/credentials.yml.enc` (encrypted) is the Rails secrets mechanism. Flag plaintext secrets in `config/secrets.yml`, `config/database.yml`, or `.env` files committed to VCS without encryption.

## Still a real sink (do not suppress)

- `where("status = '#{params[:status]}'")`  — interpolated SQL string conditions
- `.order(params[:column])` without an explicit allowlist array/hash guard
- `find_by_sql("SELECT ... #{user_input}")`
- `<%= raw(user_input) %>` and `<%= user_input.html_safe %>`
- `skip_before_action :verify_authenticity_token` on state-changing actions
- `params.permit!` — blanket allowance of all parameters
- `config.action_dispatch.cookies_serializer = :marshal`
- `Marshal.load(Base64.decode64(cookies[:data]))` or similar patterns
- `secret_key_base` as a literal string in committed config files
- `config.force_ssl = false` in `config/environments/production.rb`
