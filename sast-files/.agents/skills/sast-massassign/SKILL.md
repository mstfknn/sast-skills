---
name: sast-massassign
description: >-
  Detect mass assignment vulnerabilities where user-supplied request data is
  bound directly to ORM model instances without an explicit field allow-list,
  enabling privilege escalation via overposting of sensitive fields such as
  is_admin, role, or balance. Covers Rails, Django, Spring, Express, Laravel,
  and ASP.NET. Requires sast/architecture.md (run sast-analysis first). Outputs
  findings to sast/massassign-results.md and sast/massassign-results.json. Use
  when asked to find mass assignment, overposting, or parameter binding bugs.
version: 0.1.0
---

# Mass Assignment Detection

You are performing a focused security assessment to find mass assignment vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find unsafe parameter binding sites), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file and the canonical JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Mass Assignment

Mass assignment (also called overposting or auto-binding) occurs when a web framework automatically maps HTTP request parameters onto the fields of a model or entity class without restricting which fields are allowed. An attacker can include extra fields — not shown in any form — in the request body, potentially setting `is_admin`, `role`, `balance`, `confirmed`, or any other sensitive attribute stored on the model.

The core pattern: *an unfiltered user-supplied map (request body, query params, form data) is passed directly to a model constructor, update method, or fill method without an explicit field allow-list.*

### What Mass Assignment IS

- Rails `User.new(params[:user])` or `User.update(params[:user])` without `params.require().permit(...)` guard
- Rails `params.permit!` — permits every key unconditionally, effectively removing the allow-list
- Django `ModelForm` using `fields = '__all__'` or `exclude = []` with no further field filtering
- Django passing `**request.POST.dict()` or `**request.data` directly to a model constructor
- Spring `@ModelAttribute` binding to a JPA/Hibernate entity class rather than a dedicated DTO
- Spring `BeanUtils.copyProperties(source, entity)` where `source` is a bound request object containing sensitive entity fields
- Express (Node.js) `Object.assign(user, req.body)`, `_.merge(user, req.body)`, `User.create(req.body)`, `User.update(req.body)` without picking safe fields
- Laravel `Model::create($request->all())` or `$model->fill($request->all())` on a model with no `$fillable` list or with `$guarded = []`
- ASP.NET `[Bind]` attribute on an action parameter with no `Include` list, or `TryUpdateModelAsync(entity)` without specifying a property allowlist

### What Mass Assignment is NOT

Do not flag these patterns:

- **Rails safe strong params**: `params.require(:user).permit(:name, :email)` — the allow-list is present; this is safe
- **Django serializer with explicit fields**: `class UserSerializer(ModelSerializer): fields = ['name', 'email']` — only those fields are accepted
- **Django ModelForm with `exclude`** pointing to every sensitive field — technically safe but fragile; flag only if sensitive fields could still slip through
- **Spring DTO binding**: `@ModelAttribute UserRegistrationDto dto` where the DTO class exposes only safe fields with no sensitive entity fields — safe
- **Express explicit field picking**: `User.create({ name: req.body.name, email: req.body.email })` — only named fields, safe
- **Laravel with explicit `$fillable`**: a `User` model that declares `protected $fillable = ['name', 'email']` and uses `Model::create($request->all())` — the `$fillable` list guards it; this is safe
- **Laravel guarded only on `id`**: `$guarded = ['id']` when the model has `is_admin`, `role`, etc. — **still vulnerable**, flag it

### Framework-Specific FP Killers (Safe Patterns)

**Rails:**
```ruby
# SAFE — explicit allow-list via strong parameters
def user_params
  params.require(:user).permit(:name, :email, :password)
end
User.new(user_params)
User.update(user_params)

# UNSAFE — permit! removes the allow-list
def user_params
  params.require(:user).permit!   # flag this
end

# UNSAFE — raw params hash passed directly
User.new(params[:user])           # flag this (no permit/require chain)
```

**Django:**
```python
# SAFE — serializer with explicit field list
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']   # explicit — safe

# UNSAFE — all fields accepted
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'               # flag this

# UNSAFE — direct constructor population from request data
user = User(**request.data)             # flag this
user = User(**request.POST.dict())      # flag this

# SAFE — ModelForm with explicit fields list used at validation boundary
class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']  # explicit — safe
```

**Spring:**
```java
// UNSAFE — entity bound directly to @ModelAttribute
@PostMapping("/register")
public ResponseEntity<?> register(@ModelAttribute User user) { ... }   // flag this

// UNSAFE — BeanUtils copies all source properties including is_admin
BeanUtils.copyProperties(userRequest, userEntity);                      // flag this unless source is a DTO with no sensitive fields

// SAFE — DTO class exposes only safe fields; entity populated manually
@PostMapping("/register")
public ResponseEntity<?> register(@ModelAttribute @Valid UserRegistrationDto dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());   // no is_admin / role setters called
    ...
}

// SAFE — @InitBinder restricts allowed fields
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "password");
}
```

**Express / Node.js:**
```javascript
// UNSAFE — full request body assigned to model
const user = await User.create(req.body);                    // flag this
Object.assign(existingUser, req.body);                       // flag this
_.merge(existingUser, req.body);                             // flag this

// SAFE — explicit field picking
const { name, email } = req.body;
const user = await User.create({ name, email });             // safe — only named fields

// SAFE — lodash pick with allowlist
const safeData = _.pick(req.body, ['name', 'email']);
const user = await User.create(safeData);                    // safe
```

**Laravel:**
```php
// UNSAFE — $request->all() with no $fillable guard
User::create($request->all());          // flag if model has no $fillable or $guarded is wide
$user->fill($request->all());           // same

// SAFE — $request->only() with allowlist
User::create($request->only(['name', 'email', 'password']));  // safe

// SAFE — model with tight $fillable
// In User.php: protected $fillable = ['name', 'email'];
// Then: User::create($request->all()); — the $fillable list guards it, safe

// UNSAFE — $guarded = [] disables all protection
// In User.php: protected $guarded = [];
// Then: User::create($request->all()); — flag this
```

**ASP.NET MVC / Core:**
```csharp
// UNSAFE — [Bind] without Include; all public properties mapped
[HttpPost]
public ActionResult Edit([Bind] User user) { ... }               // flag this

// UNSAFE — TryUpdateModelAsync on entity without property list
await TryUpdateModelAsync(user);                                 // flag this

// SAFE — [Bind] with explicit Include list
public ActionResult Edit([Bind(Include = "Name,Email")] User user) { ... }  // safe

// SAFE — ViewModel / DTO with no sensitive fields, mapped manually
public ActionResult Edit(UserEditViewModel vm) {
    var user = db.Users.Find(vm.Id);
    user.Name = vm.Name;
    user.Email = vm.Email;   // is_admin never touched
    db.SaveChanges();
}

// SAFE — TryUpdateModelAsync with property expression list
await TryUpdateModelAsync(user, "", u => u.Name, u => u.Email); // explicit properties, safe
```

---

## Vulnerable vs. Secure Examples

### Ruby on Rails

```ruby
# VULNERABLE: raw params hash — no strong parameter allow-list
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    if @user.update(params[:user])   # attacker sends {"user":{"is_admin":true}}
      redirect_to @user
    else
      render :edit
    end
  end
end

# VULNERABLE: permit! removes allow-list entirely
def user_params
  params.require(:user).permit!
end

# SECURE: explicit strong params allow-list
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    if @user.update(user_params)
      redirect_to @user
    else
      render :edit
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :password)
  end
end
```

### Django REST Framework

```python
# VULNERABLE: ModelSerializer with fields = '__all__'
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'    # is_admin, role, balance all accepted from request

class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

# VULNERABLE: direct **request.data expansion
@api_view(['POST'])
def register(request):
    user = User(**request.data)   # attacker can set is_admin=True
    user.save()
    return Response({'id': user.id})

# SECURE: explicit field list on serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

# SECURE: read_only_fields for sensitive attributes
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'is_admin']
        read_only_fields = ['is_admin']
```

### Django ModelForm

```python
# VULNERABLE: __all__ exposes every field
class UserEditForm(ModelForm):
    class Meta:
        model = User
        fields = '__all__'

def edit_user(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=user)
        if form.is_valid():
            form.save()   # saves is_admin / role from POST

# SECURE: explicit fields list
class UserEditForm(ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
```

### Spring Boot

```java
// VULNERABLE: @ModelAttribute binds directly to entity
@RestController
@RequestMapping("/api/users")
public class UserController {

    @PutMapping("/{id}")
    public ResponseEntity<User> update(
            @PathVariable Long id,
            @ModelAttribute User userFromRequest) {   // attacker sends isAdmin=true
        User existing = userRepository.findById(id).orElseThrow();
        BeanUtils.copyProperties(userFromRequest, existing, "id");  // copies isAdmin!
        return ResponseEntity.ok(userRepository.save(existing));
    }
}

// VULNERABLE: BeanUtils.copyProperties with no ignore list on sensitive entity
BeanUtils.copyProperties(requestBody, userEntity);   // copies every property

// SECURE: use a DTO with only safe fields, map manually
public class UserUpdateDto {
    private String name;
    private String email;
    // No isAdmin, no role — not even a field
    // getters/setters...
}

@PutMapping("/{id}")
public ResponseEntity<User> update(@PathVariable Long id,
                                   @RequestBody @Valid UserUpdateDto dto) {
    User user = userRepository.findById(id).orElseThrow();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    return ResponseEntity.ok(userRepository.save(user));
}

// SECURE: @InitBinder restricts allowed fields on the controller
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "password");
}
```

### Express / Node.js (Mongoose / Sequelize)

```javascript
// VULNERABLE: req.body passed directly to Model.create
app.post('/api/users', async (req, res) => {
  try {
    const user = await User.create(req.body);   // attacker: {"name":"x","isAdmin":true}
    res.status(201).json(user);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// VULNERABLE: Object.assign spreads request body onto existing document
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);   // is_admin, role overwritten from body
  await user.save();
  res.json(user);
});

// VULNERABLE: _.merge (also recurses into nested objects)
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  _.merge(user, req.body);   // same problem, also prototype pollution risk
  await user.save();
  res.json(user);
});

// SECURE: explicit field destructuring
app.post('/api/users', async (req, res) => {
  const { name, email, password } = req.body;
  const user = await User.create({ name, email, password });
  res.status(201).json(user);
});

// SECURE: lodash pick with allowlist
app.put('/api/users/:id', async (req, res) => {
  const ALLOWED_FIELDS = ['name', 'email', 'bio'];
  const safeUpdates = _.pick(req.body, ALLOWED_FIELDS);
  const user = await User.findByIdAndUpdate(req.params.id, safeUpdates, { new: true });
  res.json(user);
});
```

### Laravel

```php
// VULNERABLE: $request->all() — no $fillable guard
class UserController extends Controller
{
    public function update(Request $request, User $user)
    {
        $user->fill($request->all());   // attacker sends is_admin=1
        $user->save();
        return response()->json($user);
    }

    public function store(Request $request)
    {
        $user = User::create($request->all());   // same problem
        return response()->json($user, 201);
    }
}

// ALSO VULNERABLE in User model:
// protected $guarded = [];   // disables all mass-assignment protection

// SECURE: $request->only() with explicit allowlist
public function update(Request $request, User $user)
{
    $user->fill($request->only(['name', 'email', 'bio']));
    $user->save();
    return response()->json($user);
}

// SECURE: tight $fillable on the model
// In User.php:
// protected $fillable = ['name', 'email', 'password'];
// Then User::create($request->all()) is safe because $fillable gates it.
```

### ASP.NET Core

```csharp
// VULNERABLE: no [Bind] Include, all public properties bound
[HttpPost]
public async Task<IActionResult> Create([FromBody] User user)
{
    // user.IsAdmin could be true if attacker sent it in the JSON body
    _context.Users.Add(user);
    await _context.SaveChangesAsync();
    return Ok(user);
}

// VULNERABLE: TryUpdateModelAsync with no property list
[HttpPut("{id}")]
public async Task<IActionResult> Edit(int id)
{
    var user = await _context.Users.FindAsync(id);
    await TryUpdateModelAsync(user);   // every HTTP field bound including IsAdmin
    await _context.SaveChangesAsync();
    return Ok(user);
}

// SECURE: ViewModel / DTO with only safe properties
public class UserUpdateViewModel
{
    public string Name { get; set; }
    public string Email { get; set; }
    // IsAdmin not present
}

[HttpPut("{id}")]
public async Task<IActionResult> Edit(int id, [FromBody] UserUpdateViewModel vm)
{
    var user = await _context.Users.FindAsync(id);
    user.Name = vm.Name;
    user.Email = vm.Email;
    await _context.SaveChangesAsync();
    return Ok(user);
}

// SECURE: TryUpdateModelAsync with explicit property expression list
await TryUpdateModelAsync(user, "", u => u.Name, u => u.Email);
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Unsafe Parameter Binding Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where HTTP request data (body, query params, form data) is passed to a model constructor, update method, or fill method without an explicit field allow-list. Write results to `sast/massassign-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, ORM, model classes, and request handling layer.
>
> **What to search for — vulnerable binding patterns by framework**:
>
> Do NOT trace user input yet — that is Phase 2's job. In Phase 1, flag any call where request data (or a variable that appears to be request-derived) reaches a model binding site without obvious allow-list filtering in the immediate vicinity.
>
> **1. Rails (Ruby)**
>
> Search for:
> - `Model.new(params[` without a `.permit(` or `.permit!` guard
> - `Model.update(params[` without a `.permit(` or `.permit!` guard
> - `model.update(params[` without a `.permit(` or `.permit!` guard
> - `.permit!` anywhere — this removes the allow-list and is always a finding
> - `params[:` passed directly as the argument to `.new(`, `.update(`, `.create(`
>
> Grep patterns:
> ```
> grep -rn "\.new(params\b" --include="*.rb"
> grep -rn "\.update(params\b" --include="*.rb"
> grep -rn "\.create(params\b" --include="*.rb"
> grep -rn "permit!" --include="*.rb"
> grep -rn "params\[" --include="*.rb"
> ```
>
> **2. Django (Python)**
>
> Search for:
> - `fields = '__all__'` inside `ModelForm` or `ModelSerializer` Meta classes
> - `exclude = []` (empty exclude — effectively all fields allowed)
> - `**request.POST` or `**request.data` or `**request.POST.dict()` passed to a model constructor
> - `ModelForm(request.POST` — check the form's Meta.fields value
>
> Grep patterns:
> ```
> grep -rn "fields = '__all__'" --include="*.py"
> grep -rn 'fields = "__all__"' --include="*.py"
> grep -rn "\*\*request\.POST" --include="*.py"
> grep -rn "\*\*request\.data" --include="*.py"
> grep -rn "ModelForm(request\.POST" --include="*.py"
> grep -rn "exclude = \[\]" --include="*.py"
> ```
>
> **3. Spring (Java)**
>
> Search for:
> - `@ModelAttribute` on controller method parameters where the parameter type is a JPA entity (has `@Entity` annotation) — not a DTO
> - `BeanUtils.copyProperties(` — check source type; if source is a request-bound object with no DTO restriction, flag it
> - `@RequestBody` on parameters whose type is an entity class
>
> Grep patterns:
> ```
> grep -rn "@ModelAttribute" --include="*.java"
> grep -rn "BeanUtils\.copyProperties" --include="*.java"
> grep -rn "@RequestBody" --include="*.java"
> ```
>
> For each `@ModelAttribute` hit, look up the parameter's type — if it has `@Entity` or `@Table` annotation, it is a direct entity bind.
>
> **4. Express / Node.js**
>
> Search for:
> - `Object.assign(` where one operand is `req.body` or `request.body`
> - `_.merge(` where one operand is `req.body`
> - `Model.create(req.body)` or `Model.create(request.body)`
> - `Model.update(req.body)` or `.findByIdAndUpdate(id, req.body`
> - `.insertOne(req.body)`, `.insertMany(req.body)`
>
> Grep patterns:
> ```
> grep -rn "Object\.assign(" --include="*.js" --include="*.ts"
> grep -rn "\.create(req\.body" --include="*.js" --include="*.ts"
> grep -rn "\.create(request\.body" --include="*.js" --include="*.ts"
> grep -rn "findByIdAndUpdate" --include="*.js" --include="*.ts"
> grep -rn "_\.merge(" --include="*.js" --include="*.ts"
> grep -rn "insertOne(req\.body\|insertMany(req\.body" --include="*.js" --include="*.ts"
> ```
>
> **5. Laravel (PHP)**
>
> Search for:
> - `$request->all()` passed to `Model::create(`, `$model->fill(`
> - `$request->all()` assigned to a variable later passed to create/fill
> - Models with `protected $guarded = []` — always a flag
> - Models with NO `$fillable` and NO `$guarded`
>
> Grep patterns:
> ```
> grep -rn "\$request->all()" --include="*.php"
> grep -rn "::create(\\\$request" --include="*.php"
> grep -rn "->fill(\\\$request" --include="*.php"
> grep -rn "guarded = \[\]" --include="*.php"
> grep -rn "\\\$fillable" --include="*.php"
> ```
>
> **6. ASP.NET (C#)**
>
> Search for:
> - `[Bind]` attribute on action parameters with no `Include` property
> - `TryUpdateModelAsync(` calls with no property expression list (fewer than 3 arguments)
> - `[FromBody]` on parameters whose type is an EF Core entity class
>
> Grep patterns:
> ```
> grep -rn "\[Bind\]" --include="*.cs"
> grep -rn "TryUpdateModelAsync(" --include="*.cs"
> grep -rn "\[FromBody\]" --include="*.cs"
> ```
>
> **Output format** — write to `sast/massassign-recon.md`:
>
> ```markdown
> # Mass Assignment Recon: [Project Name]
>
> ## Summary
> Found [N] candidate mass assignment sites.
>
> ## Candidate Sites
>
> ### 1. [Descriptive name — e.g., "User.create(req.body) in registration endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Framework / Pattern**: [Rails params.permit! / Django __all__ / Spring @ModelAttribute entity / Express Object.assign(req.body) / Laravel $request->all() / ASP.NET [Bind] without Include]
> - **Endpoint / Function**: [route or controller action or function name]
> - **Model / Entity**: [name of the model class or table, if determinable]
> - **Binding expression**: [exact snippet showing the unsafe binding]
> - **Code snippet**:
>   ```
>   [the binding site and surrounding 3-5 lines of context]
>   ```
> - **Sensitive fields on model (if determinable)**: [e.g., is_admin, role, balance — or "unknown, check Phase 2"]
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/massassign-recon.md`. If the recon found **zero candidate sites** (the summary reports "Found 0" or the "Candidate Sites" section is empty or absent), skip Phase 2 entirely. Instead, write the following files and stop:

**`sast/massassign-results.md`:**
```markdown
# Mass Assignment Analysis Results

No vulnerabilities found.
```

**`sast/massassign-results.json`:**
```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one candidate site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/massassign-recon.md` and split the candidate sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/massassign-recon.md` and count the numbered sections under "Candidate Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/massassign-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary framework from `sast/architecture.md` and include the matching examples from the "Vulnerable vs. Secure Examples" section above in each subagent's instructions where indicated by `[FRAMEWORK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate mass assignment site, determine whether user-supplied data genuinely reaches the model binding call without an effective allow-list, making it exploitable for privilege escalation. Write results to `sast/massassign-batch-[N].md`.
>
> **Your assigned candidate sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, authentication, and model schema.
>
> **Verify question**: Is a user-supplied map (request body, form data, query params) passed to a model constructor or update/fill method **without** an effective field allow-list?
>
> **Taint analysis — trace the binding expression backwards:**
>
> 1. **Confirm the source is HTTP request data**: Follow the binding expression's argument back. Is it `request.body`, `req.body`, `params[:x]`, `request.POST`, `$request->all()`, a form data object, or a variable ultimately assigned from these? If the data originates from internal server logic only (config, database read, hardcoded map), it is NOT a mass assignment vulnerability.
>
> 2. **Check for an effective allow-list between source and sink**:
>    - Rails: Is there a `.permit(:field1, :field2, ...)` call (without `!`) on the params object before it is passed to the model? If yes, safe. If `.permit!` or no `permit` at all, vulnerable.
>    - Django serializer: Does the Meta class have `fields = [...]` (an explicit list, not `'__all__'`)? If yes, safe. If `fields = '__all__'` or absent, vulnerable.
>    - Django ModelForm: Same check. `fields = '__all__'` or `exclude = []` = vulnerable.
>    - Spring `@ModelAttribute`: Is the parameter type a DTO/view model with NO sensitive fields (no `isAdmin`, `role`, `balance`, `confirmed`, etc. properties)? If the DTO has only safe fields, safe. If it IS the entity class with sensitive fields, vulnerable.
>    - Spring `BeanUtils.copyProperties`: Does the source type (first argument) have sensitive fields that exist on the target entity? If so, vulnerable. Is there an ignoreProperties list that covers ALL sensitive fields? If yes, safe.
>    - Express `Object.assign(model, req.body)`: Is there a whitelist operation (`_.pick`, destructuring, manual field assignment) between `req.body` and the assign call? If not, vulnerable.
>    - Express `Model.create(req.body)`: Same — is `req.body` filtered before passing? If not, vulnerable.
>    - Laravel `Model::create($request->all())`: Does the model declare `$fillable` covering only safe fields? If yes, safe. Does it declare `$guarded = []`? If so, vulnerable. If no `$fillable` declared at all, check Laravel global config; if protection disabled, vulnerable.
>    - ASP.NET `TryUpdateModelAsync(entity)` with no property list: Is there a profile mapping, a ViewModel intermediary, or explicit property selection? If not, vulnerable.
>
> 3. **Assess the model for sensitive fields**: Look up the model/entity class. Does it have fields such as: `is_admin`, `isAdmin`, `admin`, `role`, `roles`, `permissions`, `balance`, `credit`, `account_balance`, `confirmed`, `verified`, `email_confirmed`, `password_reset_token`, `api_key`, `stripe_customer_id`, `plan`, `subscription_tier`? Sensitive fields raise severity to high or critical.
>
> 4. **Assess endpoint accessibility**: Is the endpoint authenticated? Does it require an admin role? An unauthenticated or low-privilege endpoint with mass assignment to sensitive fields is `exploitability: reachable`. An admin-only endpoint reduces risk. Check for `@login_required`, `authenticate_user!`, `[Authorize]`, JWT middleware, etc.
>
> **FP Killers — do NOT flag as Vulnerable if ALL of these apply**:
>
> - Rails: `params.require(:model).permit(:field1, :field2)` guard present (without `!`) before the model call.
> - Django: Serializer or ModelForm uses an explicit `fields = ['field1', 'field2']` list (not `'__all__'`).
> - Spring: The bound parameter type is a DTO class with no sensitive entity fields declared.
> - Express: `req.body` is filtered through `_.pick(req.body, ALLOWLIST)`, destructuring, or explicit field selection before the model call.
> - Laravel: Model declares `protected $fillable = [...]` listing only safe fields, AND no `protected $guarded = []`.
> - ASP.NET: `TryUpdateModelAsync` includes a property expression list OR the bound type is a ViewModel with no sensitive properties.
>
> **Severity and exploitability assignment**:
>
> - `severity: critical` — model contains `is_admin`, `role`, `balance`, or `permissions` AND the endpoint is accessible without admin role (public or low-privilege user endpoint).
> - `severity: high` — model contains sensitive fields (see list above) OR allow-list is missing and endpoint is authenticated as regular user (default when sensitive fields found).
> - `severity: medium` — model has no sensitive fields, or the only writable fields via the binding are low-risk (e.g., display name, bio).
> - `exploitability: reachable` — the endpoint is unauthenticated or accessible to any authenticated user; model has sensitive fields.
> - `exploitability: conditional` — endpoint is behind auth but no role restriction, or model sensitivity is uncertain.
> - `exploitability: unreachable` — endpoint is admin-only AND admin controls are verified in code.
> - `confidence: high` — `params.permit!`, `fields = '__all__'`, `$guarded = []`, or explicit entity-class `@ModelAttribute` seen in code.
> - `confidence: medium` — indirect binding or allow-list presence is inferred from adjacent code but not explicitly confirmed.
> - `confidence: low` — binding expression is behind multiple layers; model schema not determinable from static analysis.
>
> **chain_id**: If the same endpoint is also flagged by `sast-missingauth` for lacking authentication, assign `chain_id: "overpost-privesc"` to this finding to link the two into a combined attack chain (unauthenticated endpoint + mass assignment = privilege escalation without any account).
>
> **Framework examples for this project's tech stack**:
>
> [FRAMEWORK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Request data demonstrably reaches the model binding without an effective allow-list.
> - **Likely Vulnerable**: Request data probably reaches the binding (indirect flow) or allow-list is partial / ineffective.
> - **Not Vulnerable**: An effective allow-list (permit, explicit fields list, DTO, $fillable) is confirmed in code, or source is server-side only.
> - **Needs Manual Review**: Cannot determine model schema or allow-list presence from static analysis alone.
>
> **Output format** — write to `sast/massassign-batch-[N].md`:
>
> ```markdown
> # Mass Assignment Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / Function**: [route or action or function name]
> - **Framework pattern**: [Rails params.permit! / Django __all__ / Spring @ModelAttribute entity / Express Object.assign / Laravel $request->all() / ASP.NET TryUpdateModelAsync]
> - **Issue**: [e.g., "req.body passed directly to User.create(); isAdmin field on model is writable"]
> - **Taint trace**: [Step-by-step from request source to model binding call]
> - **Sensitive fields exposed**: [list fields like is_admin, role, balance discovered on the model, or "none identified"]
> - **Endpoint accessibility**: [public / authenticated / admin-only]
> - **Severity**: [critical|high|medium]
> - **Exploitability**: [reachable|conditional|unreachable|unknown]
> - **Confidence**: [high|medium|low]
> - **chain_id**: [overpost-privesc | null]
> - **Impact**: [e.g., "Any authenticated user can escalate to admin by POSTing isAdmin=true"]
> - **PoC request**:
>   ```
>   [HTTP request or curl command demonstrating the attack, e.g.:
>    POST /api/users HTTP/1.1
>    Content-Type: application/json
>
>    {"name":"Alice","email":"alice@example.com","isAdmin":true}
>   ]
>   ```
> - **Remediation**: [specific fix for this framework — e.g., "Use params.require(:user).permit(:name, :email) instead of params[:user]"]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / Function**: [route or function name]
> - **Issue**: [indirect binding or partial allow-list]
> - **Taint trace**: [best-effort trace; mark uncertain steps]
> - **Concern**: [why it remains a risk despite partial mitigation]
> - **Severity**: [critical|high|medium]
> - **Exploitability**: [reachable|conditional|unknown]
> - **Confidence**: [medium|low]
> - **chain_id**: [overpost-privesc | null]
> - **Remediation**: [specific fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / Function**: [route or function name]
> - **Reason**: [e.g., "params.permit(:name, :email) allow-list confirmed at line 42" or "DTO has no sensitive fields"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / Function**: [route or function name]
> - **Uncertainty**: [e.g., "Model class defined in external gem; field list unavailable via static analysis"]
> - **Suggestion**: [what to trace or check manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/massassign-batch-*.md` file and merge them into `sast/massassign-results.md` (human-readable) and `sast/massassign-results.json` (canonical schema). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/massassign-batch-1.md`, `sast/massassign-batch-2.md`, ... files.
2. Collect all findings from each batch, combining them into one list. Preserve every field.
3. Count totals across all batches for the executive summary.
4. Write the merged human report to `sast/massassign-results.md`:

```markdown
# Mass Assignment Analysis Results: [Project Name]

## Executive Summary
- Candidate sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Attack Chain Notes
- Findings with chain_id "overpost-privesc" should be correlated with sast-missingauth results.
  An unauthenticated endpoint + mass assignment with is_admin/role on the model = critical combined severity.

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical JSON to `sast/massassign-results.json`. Build the `findings` array from all VULNERABLE and LIKELY VULNERABLE findings (omit NOT VULNERABLE; include NEEDS MANUAL REVIEW with `confidence: low`). Assign sequential IDs starting at `massassign-001`.

The canonical finding schema (emit exactly these fields):

```json
{
  "findings": [
    {
      "id": "massassign-001",
      "skill": "sast-massassign",
      "severity": "critical",
      "title": "User.create(req.body) binds full request body including isAdmin",
      "description": "The /api/users registration endpoint passes req.body directly to User.create(). The User model has an isAdmin field. Any caller can set isAdmin: true in the request body to gain administrator privileges. Endpoint is accessible without authentication.",
      "location": { "file": "src/routes/users.js", "line": 34, "column": 22 },
      "remediation": "Destructure only safe fields: const { name, email, password } = req.body; User.create({ name, email, password }). Never pass req.body directly to model constructors.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "overpost-privesc"
    }
  ]
}
```

Use `"findings": []` if no exploitable findings were identified.

6. After writing both output files, **delete all intermediate files**: `sast/massassign-recon.md` and all `sast/massassign-batch-*.md` files.

---

## Chain IDs

This skill participates in the following cross-skill attack chains:

| chain_id | Description | Partner skill |
|---|---|---|
| `overpost-privesc` | Unauthenticated (or low-privilege) endpoint + mass assignment of is_admin/role/balance = full privilege escalation without any account or with a normal account | `sast-missingauth` |

When `sast-missingauth` flags an endpoint as missing authentication AND this skill flags the same endpoint for mass assignment of sensitive fields, both findings should carry `chain_id: "overpost-privesc"`. The `sast-report` aggregator uses this to surface the combined critical impact.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidate sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 7 sites, use 3 subagents (3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, plus the framework examples relevant to this project's stack.
- **Phase 1 is purely structural**: flag any binding call where a request-derived variable reaches a model constructor or update method without obvious allow-list filtering in the immediate vicinity. Do not trace user input deeply in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint + allow-list analysis**: confirm the source is HTTP request data, then confirm the absence of an effective allow-list. If both are true, it is a finding.
- For Laravel, the `$fillable` vs `$guarded` interaction is subtle: `$guarded = []` disables protection entirely even if `$fillable` exists on a parent class. Flag `$guarded = []` always.
- For Spring, `@RequestBody` on an entity class is as dangerous as `@ModelAttribute` — both bind the full JSON body to all public setters. Check the parameter type.
- `Object.assign` and `_.merge` are both dangerous. `_.merge` is additionally a prototype pollution vector — note the overlap with sast-prototype if that skill is also running.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". A missed privilege escalation is far more damaging than a false positive.
- The canonical JSON must use `"findings": []` (not omit the key) when no findings are found, so the aggregator can verify the scan ran.
- Clean up intermediate files: delete `sast/massassign-recon.md` and all `sast/massassign-batch-*.md` files after the final output files are written.
- Always emit BOTH `sast/massassign-results.md` (human) AND `sast/massassign-results.json` (canonical schema), even when the finding count is zero.
