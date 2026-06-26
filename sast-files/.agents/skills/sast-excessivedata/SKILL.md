---
name: sast-excessivedata
description: >-
  Detect Excessive Data Exposure vulnerabilities (API3:2023, CWE-213) where API
  responses serialize entire ORM objects — including password hashes, tokens,
  internal flags, and PII — instead of an explicit field allow-list. Covers
  Django REST Framework, Rails, Spring Boot, Express/Node.js, Laravel, and
  FastAPI serialization paths. Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/excessivedata-results.md. Use when asked to
  find over-exposure, mass data leakage, or API3 issues.
version: 0.1.0
---

# Excessive Data Exposure Detection

You are performing a focused security assessment to find Excessive Data Exposure vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find serializer and response sites that lack explicit field restrictions), **batched verify** (serialization-path analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Excessive Data Exposure

Excessive Data Exposure (API3:2023 / OWASP API Security Top 10, CWE-213) occurs when an API endpoint serializes and returns more data than the caller needs or is authorized to see. The most common pattern is returning a raw ORM model object — or a serializer with `fields = '__all__'` — that includes sensitive columns such as `password_hash`, `api_token`, `ssn`, `credit_card`, `secret`, or internal administrative flags. The client-side filtering anti-pattern (returning everything and relying on the frontend to hide sensitive fields) is the canonical failure mode; the fix is server-side field allow-listing.

The core pattern: *a model instance is serialized to an HTTP response without an explicit field restriction, and the model contains at least one sensitive column.*

### What Excessive Data Exposure IS

- `ModelSerializer` with `fields = '__all__'` on a model that has a `password`, `password_hash`, `token`, or `secret` column
- `render json: @user` (Rails) without `only:` or `except:`, returning the full ActiveRecord object
- `@ResponseBody` annotated Spring controller method returning a JPA/Hibernate `@Entity` directly
- `res.json(user.toObject())` in Express where `user` is a Mongoose document without `.select()` field exclusion
- `return $user` from a Laravel controller where the model has no `$hidden` property
- FastAPI path function whose `response_model` is the SQLAlchemy ORM class rather than a Pydantic DTO with a restricted field set
- GraphQL resolver returning the full ORM node when the schema exposes all fields by default
- Serializer `exclude` list that misses sensitive fields added later to the model (incomplete exclusion)
- Returning all columns from a `SELECT *` query when only a subset is needed

### What Excessive Data Exposure is NOT

Do not flag these patterns — they are effectively protected:

- **DRF serializers with an explicit field subset**: `fields = ['id', 'username', 'email']` — all unlisted columns are omitted
- **DRF serializers with a correct `exclude` tuple**: `exclude = ('password', 'api_token', 'ssn')` — only flag if the exclude list clearly misses sensitive fields
- **Rails `render json: @user, only: [:id, :name, :email]`** — the `only:` option whitelists fields
- **Rails `render json: @user, except: [:password_digest, :remember_token]`** — the `except:` option blacklists fields; still verify the blacklist is complete
- **ActiveRecord `as_json(only:)` or `to_json(except:)` with a complete restriction**
- **Spring DTOs / projection interfaces / `@JsonIgnore`** on sensitive fields — safe if every sensitive field is annotated or excluded from the DTO
- **Laravel `$hidden = ['password', 'remember_token']`** — safe when the hidden list provably covers all sensitive columns
- **FastAPI `response_model=` a Pydantic schema** (not the ORM class) that lists only the fields the caller needs
- **Express `.select('-password -token')` (Mongoose)** or `.select('id name email')` (column allowlist) at the query level
- **Admin-only endpoints** with demonstrated access control (`@IsAdminUser`, `permission_classes = [IsAdminUser]`, role check) — lower severity, not a skip; document it
- **Internal service-to-service endpoints** not reachable by end users — lower confidence, flag for manual review

### Why Server-Side Field Restriction Matters

Client-side filtering — returning all columns and hiding them in the UI or filtering them in JavaScript — is not a defense. The full response appears in the browser's DevTools Network tab, in proxy logs, and in any tool that inspects HTTP traffic. An attacker with basic tools extracts all fields regardless of what the frontend renders. The server is the only trust boundary.

### Patterns That Prevent Excessive Data Exposure

**1. DRF: explicit field allow-list**
```python
# SECURE
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined']
        # password_hash, api_token, etc. are NOT listed → not serialized

# VULNERABLE
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # includes password_hash, api_token, ssn ...
```

**2. DRF: `exclude` instead of `fields` (higher FP risk — verify the list)**
```python
# SECURE only if the exclude list is complete and stays current
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        exclude = ('password', 'api_token', 'remember_token', 'ssn')
        # Risk: a new sensitive column added to User will silently appear in responses

# BETTER: always prefer explicit fields = [...] over exclude = (...)
```

**3. Rails: `only:` / `except:` options**
```ruby
# SECURE
render json: @user, only: [:id, :username, :email]

# ALSO SECURE (but fragile — new columns appear unless re-audited)
render json: @user, except: [:password_digest, :reset_password_token, :remember_token]

# VULNERABLE
render json: @user   # no restriction → includes password_digest, remember_token, ...
@user.to_json        # same issue
```

**4. Spring: DTO / projection instead of entity**
```java
// SECURE — return a DTO, never the JPA entity
public ResponseEntity<UserDto> getUser(@PathVariable Long id) {
    User user = userRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(new UserDto(user.getId(), user.getUsername(), user.getEmail()));
}

// VULNERABLE — returns the @Entity directly, all columns exposed
@GetMapping("/users/{id}")
public ResponseEntity<User> getUser(@PathVariable Long id) {
    return ResponseEntity.ok(userRepository.findById(id).orElseThrow());
}
```

**5. Express / Mongoose: field exclusion at the query or serialization level**
```javascript
// SECURE — query-level exclusion
const user = await User.findById(req.params.id).select('-password -apiToken -ssn');
res.json(user);

// SECURE — manual DTO construction
const { _id, username, email } = await User.findById(req.params.id);
res.json({ _id, username, email });

// VULNERABLE
const user = await User.findById(req.params.id);
res.json(user.toObject());  // includes password, apiToken, ssn, ...
res.json(user);             // same — Mongoose serializes all fields
```

**6. Laravel: `$hidden` on the model**
```php
// SECURE — $hidden prevents these from appearing in toJson() / toArray()
class User extends Authenticatable {
    protected $hidden = ['password', 'remember_token', 'api_token', 'ssn'];
}

// VULNERABLE — $hidden not set or set too narrowly
class User extends Authenticatable {
    // no $hidden property → return $user serializes all columns
}
return $user;               // or User::all()->toJson()
```

**7. FastAPI: Pydantic response model (not the ORM class)**
```python
# SECURE — Pydantic DTO limits serialized fields
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    class Config:
        from_attributes = True

@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    return await db.get(User, user_id)

# VULNERABLE — response_model is the ORM class itself
from app.models import User  # SQLAlchemy ORM model

@router.get("/users/{user_id}", response_model=User)  # exposes all columns
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    return await db.get(User, user_id)
```

---

## Vulnerable vs. Secure Examples

### Python — Django REST Framework

```python
# VULNERABLE (TP from spec): fields = '__all__' on a model with a password column
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        # → serializes: id, username, email, password_hash, api_token, ssn, is_active, is_staff, ...

# Used in a view:
class UserDetailView(RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer   # ← sensitive fields flow to response
    permission_classes = [IsAuthenticated]

# SECURE (TN from spec): explicit allow-list
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        # → password_hash, api_token, ssn are NOT serialized
```

```python
# VULNERABLE: unrestricted queryset passed to serializer, no field restriction
@api_view(['GET'])
def user_list(request):
    users = User.objects.all()  # all columns
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)

# ALSO VULNERABLE: serializer.data from a serializer with no Meta.fields restriction
class LegacyUserSerializer(Serializer):
    # no fields declared → DRF auto-includes everything in the model
    pass
```

### Ruby on Rails

```ruby
# VULNERABLE: render json: @object without restriction
class UsersController < ApplicationController
  def show
    @user = User.find(params[:id])
    render json: @user  # includes password_digest, remember_token, reset_password_token
  end

  def index
    render json: User.all   # same problem at scale
  end
end

# VULNERABLE: .to_json on ActiveRecord without options
def export_user(user)
  user.to_json  # returns all columns as JSON
end

# VULNERABLE: as_json without restriction
@user.as_json  # all attributes hash

# SECURE: only: option
render json: @user, only: [:id, :username, :email, :created_at]

# SECURE: custom serializer (e.g. ActiveModel::Serializer, blueprinter, fast_jsonapi)
render json: UserBlueprint.render(@user)
```

### Java — Spring Boot

```java
// VULNERABLE: @ResponseBody returning JPA entity directly
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        // User is a @Entity with fields: id, username, email, passwordHash, apiToken, ssn
        return ResponseEntity.ok(userRepository.findById(id).orElseThrow());
    }

    @GetMapping
    public List<User> listUsers() {
        return userRepository.findAll();  // all entity fields in JSON array
    }
}

// SECURE: return a DTO
public record UserDto(Long id, String username, String email) {}

@GetMapping("/{id}")
public ResponseEntity<UserDto> getUser(@PathVariable Long id) {
    User user = userRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(new UserDto(user.getId(), user.getUsername(), user.getEmail()));
}

// ALSO SECURE: Spring Data Projection
public interface UserView {
    Long getId();
    String getUsername();
    String getEmail();
}
// UserRepository.findById(id, UserView.class) — passwordHash never loaded
```

```java
// VULNERABLE: Jackson serializes all fields including sensitive ones without @JsonIgnore
@Entity
public class User {
    private Long id;
    private String username;
    private String email;
    private String passwordHash;   // ← will appear in JSON unless annotated
    private String apiToken;       // ← same
}

// MITIGATION (fragile — annotate every sensitive field)
@JsonIgnore
private String passwordHash;
// Risk: a new sensitive field added without @JsonIgnore will leak
```

### Node.js — Express + Mongoose

```javascript
// VULNERABLE: res.json() on a full Mongoose document
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);          // Mongoose auto-serializes: password, apiToken, ssn, ...
});

// VULNERABLE: toObject() without field exclusion
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user.toObject());  // includes all fields including virtuals if configured
});

// VULNERABLE: sending Sequelize model instance directly
app.get('/users/:id', async (req, res) => {
  const user = await UserModel.findByPk(req.params.id);
  res.send(user);  // Sequelize dataValues includes all columns
});

// SECURE: query-level field selection (Mongoose)
const user = await User.findById(req.params.id).select('id username email -_id');
res.json(user);

// SECURE: manual DTO destructuring
const doc = await User.findById(req.params.id);
const { _id: id, username, email } = doc;
res.json({ id, username, email });

// SECURE: Sequelize attributes option
const user = await UserModel.findByPk(req.params.id, {
  attributes: ['id', 'username', 'email'],  // passwordHash, apiToken excluded
});
res.json(user);
```

### PHP — Laravel

```php
// VULNERABLE: returning $model from controller with no $hidden
class UserController extends Controller {
    public function show(User $user) {
        return $user;  // toJson() called automatically → all columns exposed
    }

    public function index() {
        return User::all()->toJson();  // full table dump including password
    }

    public function export() {
        return response()->json(User::all());  // same
    }
}

// VULNERABLE: model without $hidden
class User extends Authenticatable {
    // no $hidden → password, remember_token, api_token appear in JSON
    protected $fillable = ['name', 'email', 'password'];
}

// SECURE: $hidden covers all sensitive columns
class User extends Authenticatable {
    protected $hidden = ['password', 'remember_token', 'api_token', 'ssn', 'credit_card'];
}

// SECURE: API Resources (preferred)
class UserResource extends JsonResource {
    public function toArray($request) {
        return [
            'id'    => $this->id,
            'name'  => $this->name,
            'email' => $this->email,
        ];
    }
}
// In controller:
return new UserResource($user);
```

### Python — FastAPI

```python
# VULNERABLE: response_model is the SQLAlchemy ORM class
from app.db.models import User  # SQLAlchemy model with: id, username, email, password_hash, api_token

@router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)  # all columns fetched AND serialized
    return user

# ALSO VULNERABLE: no response_model → FastAPI falls back to serializing everything
@router.get("/users/{user_id}")
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    return await db.get(User, user_id)  # full ORM object serialized

# SECURE: Pydantic DTO as response_model
from pydantic import BaseModel

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    class Config:
        from_attributes = True  # Pydantic v2: model_config = ConfigDict(from_attributes=True)

@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    return await db.get(User, user_id)  # FastAPI only serializes fields in UserOut
```

---

## Sensitive Field Indicator Reference

During verify, treat any column/attribute matching these patterns as sensitive. Presence of one or more of these in the serialized model makes the finding high or critical:

| Category | Common field names |
|---|---|
| Credentials | `password`, `password_hash`, `password_digest`, `hashed_password`, `encrypted_password` |
| Tokens | `api_token`, `auth_token`, `access_token`, `refresh_token`, `reset_password_token`, `remember_token`, `confirmation_token`, `unlock_token` |
| Secrets | `secret`, `secret_key`, `signing_key`, `totp_secret`, `mfa_secret`, `otp_secret` |
| PII | `ssn`, `social_security_number`, `dob`, `date_of_birth`, `national_id`, `passport_number` |
| Financial | `credit_card`, `card_number`, `cvv`, `bank_account`, `routing_number` |
| Internal flags | `is_staff`, `is_superuser`, `is_admin`, `role`, `internal_notes`, `admin_notes` |
| Private keys | `private_key`, `rsa_key`, `ssh_key`, `ssl_cert` |

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Serialization Sites Without Field Restrictions

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a model or ORM object is serialized to an HTTP response without an explicit field allow-list or with a wildcard (`__all__`). Write results to `sast/excessivedata-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, ORM, serialization layer, and API framework.
>
> **What to search for — unrestricted serialization patterns**:
>
> Look for sites where a model instance reaches an HTTP response handler with no field restriction in the serialization path. You are NOT yet tracing whether sensitive fields actually exist on the model — that is Phase 2's job. Flag any site where the serialization is potentially unrestricted.
>
> **1. Django REST Framework**:
>    - `fields = '__all__'` in any `ModelSerializer.Meta`
>    - `ModelSerializer` subclasses with no `Meta.fields` AND no `Meta.exclude` defined
>    - `serializer.data` returned from a view where the serializer has no field restriction
>    - `Response(serializer.data)` or `JsonResponse(list(queryset.values()), safe=False)` with no `.values('col1','col2')` restriction
>    - `queryset.values()` with no column list (returns all columns)
>
> **2. Ruby on Rails**:
>    - `render json: @<variable>` with no `only:` or `except:` option (any controller action)
>    - `render json: Model.all` or `render json: Model.find(...)`
>    - `<variable>.to_json` with no `only:` or `except:` option
>    - `<variable>.as_json` with no `only:` or `except:` option
>    - `respond_with @<variable>` (implicit serialization via `responders` gem)
>
> **3. Spring Boot (Java)**:
>    - `@GetMapping` / `@PostMapping` / `@RequestMapping` methods whose return type is a `@Entity`-annotated class or `List<@Entity>` or `ResponseEntity<@Entity>`
>    - `@ResponseBody` methods returning JPA entity classes
>    - `@RestController` classes where methods return domain entity objects without a DTO wrapper
>    - Spring Data REST repositories auto-exposing `@Entity` classes via `@RepositoryRestResource`
>
> **4. Express / Node.js**:
>    - `res.json(<var>)` where `<var>` is a Mongoose document or Sequelize instance (look for assignments from `.findOne`, `.findById`, `.find`, `.findAll`, `.findByPk`)
>    - `res.send(<var>)` with the same variable types
>    - `<mongoose_doc>.toObject()` or `<mongoose_doc>.toJSON()` passed directly to response
>    - `User.find(...)` → `res.json(...)` without `.select()` in the query or destructuring before response
>
> **5. Laravel (PHP)**:
>    - `return $<model_variable>;` from a controller method (implicit `toJson()`)
>    - `return response()->json(<model_variable>)` or `return response()->json(Model::all())`
>    - `Model::all()->toJson()` returned from a route or controller
>    - Models without a `protected $hidden = [...]` property
>
> **6. FastAPI (Python)**:
>    - `@router.get(...)` / `@app.get(...)` decorated functions with `response_model=<OrmClass>` where the class is a SQLAlchemy model (not a Pydantic schema)
>    - Route functions with no `response_model` parameter that return an ORM object
>    - `from_orm()` calls where the target schema has `class Config: orm_mode = True` but no field restriction
>
> **What to skip** (these are safe restriction patterns — do not flag):
> - DRF: `fields = ['col1', 'col2', ...]` (explicit list, not `'__all__'`)
> - DRF: `exclude = ('password', ...)` — flag only if list appears clearly incomplete
> - Rails: `render json: @user, only: [...]` or `render json: @user, except: [...]`
> - Rails: Blueprint / ActiveModel::Serializer / fast_jsonapi gem usage (custom serializer)
> - Spring: method returning a DTO/record/POJO class that is NOT a `@Entity`
> - Express: `.select('-password -token')` at the Mongoose query level
> - Express: manual destructuring before `res.json()` (e.g., `const {id, name} = user; res.json({id,name})`)
> - Laravel: `return new UserResource($user);` (API Resource usage)
> - Laravel: model with `protected $hidden` covering the sensitive fields
> - FastAPI: `response_model=UserOut` where `UserOut` is a Pydantic schema with explicit fields
>
> **Output format** — write to `sast/excessivedata-recon.md`:
>
> ```markdown
> # Excessive Data Exposure Recon: [Project Name]
>
> ## Summary
> Found [N] serialization sites that lack explicit field restrictions.
>
> ## Unrestricted Serialization Sites
>
> ### 1. [Descriptive name — e.g., "UserSerializer with fields='__all__'"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Framework / layer**: [DRF serializer / Rails controller / Spring controller / Express route / Laravel controller / FastAPI route]
> - **Serialization pattern**: [fields='__all__' / render json without only: / ResponseEntity<Entity> / res.json(doc) / return $model / response_model=OrmClass]
> - **Model / entity**: [User / Order / Product / unknown — infer from code]
> - **Endpoint or function**: [route path or function name]
> - **Code snippet**:
>   ```
>   [the serialization site — include enough context to identify the model and restriction (or lack thereof)]
>   ```
> - **Restriction present?**: [None / Partial (exclude list) / Unknown]
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/excessivedata-recon.md`. If the recon found **zero unrestricted serialization sites** (the summary reports "Found 0" or the "Unrestricted Serialization Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/excessivedata-results.md` and `sast/excessivedata-results.json`, then stop:

```markdown
# Excessive Data Exposure Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one unrestricted serialization site.

### Phase 2: Verify — Serialization-Path Analysis (Batched)

After Phase 1 completes, read `sast/excessivedata-recon.md` and split the sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent confirms whether sensitive fields actually exist on the model and whether a restriction is present, and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/excessivedata-recon.md` and count the numbered site sections under "Unrestricted Serialization Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/excessivedata-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned serialization site, determine whether sensitive fields actually flow into the HTTP response. Confirm or refute each recon finding. Write results to `sast/excessivedata-batch-[N].md`.
>
> **Your assigned sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the model schema, access control layer, and serialization framework.
>
> **Verify question**: Does the serialization path from the model instance to the HTTP response body include one or more sensitive fields (password, token, secret, ssn, credit_card, api_key, etc.) that a regular caller should not see?
>
> **Step-by-step verification process**:
>
> 1. **Identify the model / entity**: From the recon snippet, determine which model class is being serialized (e.g., `User`, `Account`, `Customer`).
>
> 2. **Find the model definition**: Read the model file (e.g., `models.py`, `models/user.rb`, `User.java`, `User.js`, `User.php`) and list all columns/fields.
>
> 3. **Check for sensitive fields**: Compare the model's field list against the Sensitive Field Indicator Reference:
>    - Credentials: `password`, `password_hash`, `password_digest`, `encrypted_password`
>    - Tokens: `api_token`, `auth_token`, `access_token`, `refresh_token`, `reset_password_token`, `remember_token`
>    - Secrets: `secret`, `totp_secret`, `mfa_secret`
>    - PII: `ssn`, `dob`, `national_id`
>    - Financial: `credit_card`, `card_number`, `cvv`
>    - Internal: `is_superuser`, `is_staff`, `is_admin`, `internal_notes`
>
> 4. **Confirm the restriction**: Read the serializer/response code carefully:
>    - DRF: Is `fields` set to an explicit list (safe) or `'__all__'` (vulnerable)?
>    - DRF: Is `exclude` set — and does it cover ALL sensitive fields you found in step 3?
>    - Rails: Is `only:` or `except:` passed to `render json:`? Is `except:` complete?
>    - Spring: Is the return type a `@Entity` (vulnerable) or a DTO class with no sensitive fields?
>    - Express: Is `.select()` used at the query level, or is the document destructured before serialization?
>    - Laravel: Does the model have `protected $hidden` covering all sensitive fields?
>    - FastAPI: Is `response_model` a Pydantic schema (safe) or the ORM class itself (vulnerable)?
>
> 5. **Check access control**: Is the endpoint protected by authentication or authorization?
>    - If sensitive fields are exposed AND the endpoint is unauthenticated → `exploitability: reachable`, severity → critical
>    - If sensitive fields are exposed AND the endpoint requires authentication but not elevated roles → `exploitability: reachable`, severity → high
>    - If sensitive fields are exposed AND the endpoint is admin-only with verified access control → `exploitability: conditional`, severity → medium
>    - If unsure about access control → `exploitability: unknown`, `confidence: medium`
>
> **False-positive killers** — these patterns mean the site is NOT vulnerable:
> - DRF `fields = ['id', 'name', 'email']` — explicit list excludes all unlisted sensitive fields
> - DRF `exclude = ('password', 'api_token', 'ssn', 'credit_card')` AND your model field scan confirms no other sensitive columns exist
> - Rails `render json: @user, only: [:id, :username, :email]`
> - Rails `render json: @user, except: [:password_digest, :reset_password_token, :remember_token]` AND the except list is complete
> - Spring method returning a DTO/record where the DTO class has no sensitive fields
> - Express `.select('-password -apiToken')` at query level — those fields are never loaded
> - Laravel model with `protected $hidden = ['password', 'remember_token', 'api_token']` AND the hidden list covers all sensitive fields you found
> - FastAPI `response_model=UserOut` where `UserOut` is a Pydantic schema with `fields = ['id', 'username', 'email']`
>
> **Incomplete exclusion** — flag these as medium confidence vulnerabilities:
> - DRF `exclude = ('password',)` when model also has `api_token`, `ssn`, or `credit_card` NOT in the exclude list
> - Rails `except: [:password_digest]` when model also has `remember_token`, `reset_password_token`
> - Laravel `$hidden = ['password']` when model also has `api_token`, `ssn`
>
> **Exploitability and confidence guidance**:
> - `exploitability: reachable` — sensitive fields confirmed in model AND no field restriction AND endpoint accessible to non-admin users
> - `exploitability: conditional` — sensitive fields confirmed BUT endpoint is admin-only or the access control is clear
> - `exploitability: unknown` — cannot determine model fields (abstract class, dynamic schema, external ORM)
> - `confidence: high` — `fields = '__all__'` on a model with a visible `password` column
> - `confidence: medium` — model fields must be inferred from migrations or partial schema
> - `confidence: low` — model schema not visible in the repo (e.g., external DB, generated schema)
>
> **Chains with `sast-missingauth`**: If the endpoint is confirmed unauthenticated AND exposes sensitive fields, set `chain_id: "data-overexposure"`. The `sast-missingauth` skill may find the same endpoint; the shared chain_id links them.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Confirmed**: Sensitive fields in model AND no restriction in serializer AND response is user-reachable
> - **Likely**: Sensitive fields probably present (inferred from model name/conventions) AND no restriction
> - **False Positive**: Field restriction confirmed effective, or no sensitive fields in model
> - **Needs Manual Review**: Model definition not visible or access control indeterminate
>
> **Output format** — write to `sast/excessivedata-batch-[N].md`:
>
> ```markdown
> # Excessive Data Exposure Batch [N] Results
>
> ## Findings
>
> ### [CONFIRMED] Descriptive name
> - **File**: `path/to/serializer_or_controller.ext` (lines X-Y)
> - **Endpoint / function**: [route path or function name]
> - **Model**: [ModelClass] in `path/to/model.ext`
> - **Issue**: [e.g., "UserSerializer with fields='__all__' on User model exposes password_hash and api_token"]
> - **Sensitive fields exposed**: [`password_hash`, `api_token`, `ssn`] — found in model at lines Z
> - **Missing restriction**: [e.g., "fields = '__all__' — no field allowlist"]
> - **Access control**: [Unauthenticated / Requires login / Admin-only / Unknown]
> - **Exploitability**: [reachable / conditional / unknown] — [one-line rationale]
> - **Confidence**: [high / medium / low] — [one-line rationale]
> - **Chain**: [chain_id "data-overexposure" if endpoint is also missing auth, else null]
> - **Remediation**: [e.g., "Change fields = '__all__' to fields = ['id', 'username', 'email']"]
> - **Proof of concept**:
>   ```
>   curl -s https://app.example.com/api/users/1 | python3 -m json.tool
>   # Expected: response includes "password_hash", "api_token" fields
>   ```
>
> ### [LIKELY] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route]
> - **Model**: [ModelClass]
> - **Issue**: [probable exposure — model fields partially inferred]
> - **Sensitive fields likely exposed**: [field list with inference note]
> - **Missing restriction**: [what's missing]
> - **Access control**: [status]
> - **Concern**: [why it's a risk despite uncertainty]
> - **Remediation**: [fix]
>
> ### [FALSE POSITIVE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route]
> - **Reason**: [e.g., "fields = ['id','username','email'] — password_hash not serialized" or "model has no sensitive columns"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route]
> - **Uncertainty**: [e.g., "Model defined via dynamic schema; cannot enumerate columns without runtime inspection"]
> - **Suggestion**: [what to check manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/excessivedata-batch-*.md` file and merge them into a single `sast/excessivedata-results.md` and a `sast/excessivedata-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/excessivedata-batch-1.md`, `sast/excessivedata-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving all detail fields. Count totals across all batches.
3. Assign a sequential `id` to each confirmed or likely finding: `excessivedata-001`, `excessivedata-002`, etc. Order: CONFIRMED first, then LIKELY, then NEEDS MANUAL REVIEW.
4. Write the merged human-readable report to `sast/excessivedata-results.md`:

```markdown
# Excessive Data Exposure Analysis Results: [Project Name]

## Executive Summary
- Serialization sites analyzed: [total across all batches]
- Confirmed: [N]
- Likely: [N]
- False Positives: [N]
- Needs Manual Review: [N]

## Findings

[All CONFIRMED findings first, then LIKELY, then NEEDS MANUAL REVIEW, then FALSE POSITIVES.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical JSON to `sast/excessivedata-results.json`. For each CONFIRMED or LIKELY finding (not false positives; include NEEDS MANUAL REVIEW only when confidence >= medium), emit one entry in the `findings` array using the exact schema:

```json
{
  "findings": [
    {
      "id": "excessivedata-001",
      "skill": "sast-excessivedata",
      "severity": "critical|high|medium|low",
      "title": "UserSerializer exposes password_hash via fields='__all__'",
      "description": "The UserSerializer in app/serializers.py uses fields='__all__', causing the password_hash, api_token, and ssn columns of the User model to be included in every /api/users/{id} response. Any authenticated user can retrieve these fields by inspecting the API response.",
      "location": { "file": "app/serializers.py", "line": 12, "column": 9 },
      "remediation": "Replace fields = '__all__' with an explicit allow-list: fields = ['id', 'username', 'email', 'date_joined']. Never return raw ORM objects or use wildcard serialization in API responses.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "data-overexposure"
    }
  ]
}
```

**Severity assignment rules**:
- `critical`: sensitive fields (password hash, API key, SSN, credit card) exposed AND endpoint is unauthenticated
- `high`: sensitive fields exposed AND endpoint requires authentication but not elevated roles (default for most confirmed findings)
- `medium`: sensitive fields exposed AND endpoint is admin-only with verified access control, OR exposure is only internal flags (`is_staff`, `is_admin`)
- `low`: non-sensitive excess fields exposed (e.g., internal timestamps, soft-delete flags with no security relevance)

Set `chain_id: "data-overexposure"` when the endpoint also appears (or is likely to appear) in `sast-missingauth` findings. Otherwise set `chain_id: null`.

6. After writing both output files, **delete all intermediate files**: `sast/excessivedata-recon.md` and all `sast/excessivedata-batch-*.md` files.

---

## Chain ID Reference

| chain_id | Meaning |
|---|---|
| `"data-overexposure"` | The endpoint both lacks authentication (`sast-missingauth`) AND returns sensitive fields without restriction. The combination amplifies severity: an unauthenticated caller can harvest credentials, PII, or tokens. Set this chain_id on findings from BOTH skills when they co-occur on the same endpoint so the triage and export steps can correlate them. |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 serialization sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any serialization site that lacks a visible field restriction. Do not look up model schemas in Phase 1 — that is Phase 2's job.
- **Phase 2 is both structural and semantic**: read the model definition to enumerate actual columns, then confirm whether the serialization path exposes sensitive ones.
- The `fields = '__all__'` DRF pattern is the highest-signal TP: if the `User` model has a `password` column, classify as CONFIRMED with `confidence: high`.
- The TN from the spec: `fields = ['id', 'username', 'email']` must be classified FALSE POSITIVE — the password_hash column is not in the list and is never serialized.
- Incomplete `exclude` lists are medium-confidence findings: the developer intended to restrict output but missed columns. Flag as LIKELY.
- `$hidden` in Laravel is model-level protection — it covers all serialization paths for that model. If the hidden list is complete, do not flag the controller.
- Spring Data REST `@RepositoryRestResource` auto-exposes `@Entity` classes. This is a recon target even without an explicit controller method.
- For `NEEDS MANUAL REVIEW` findings where model fields cannot be determined from static analysis (e.g., dynamically generated schema, external ORM), set `confidence: low` and include a clear suggestion for runtime inspection.
- When in doubt between LIKELY and NEEDS MANUAL REVIEW, prefer LIKELY if you have evidence of at least one sensitive field name convention in the codebase (e.g., other models have `password_hash`).
- Clean up intermediate files: delete `sast/excessivedata-recon.md` and all `sast/excessivedata-batch-*.md` files after the final output files are written.
- If `sast/excessivedata-results.md` already exists, skip this skill (the orchestrator checks for this before running).
