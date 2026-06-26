---
name: sast-zipslip
description: >-
  Detect Zip Slip / archive extraction path traversal vulnerabilities using a
  three-phase approach: recon (find archive extraction sites where entry names
  construct output paths without containment checks), batched verify (trace the
  entry name through taint and path-canonicalization analysis in parallel
  subagents, 3 sites each), and merge (consolidate batch results). Covers zip,
  tar, jar/war, cpio, and 7z extraction across Python, Java, Go, Node.js, .NET,
  and Ruby. Requires sast/architecture.md (run sast-analysis first). Outputs
  findings to sast/zipslip-results.md and sast/zipslip-results.json. Use when
  asked to find archive extraction, Zip Slip, or path traversal write bugs.
version: 0.1.0
---

# Zip Slip / Archive Extraction Path Traversal Detection

You are performing a focused security assessment to find Zip Slip vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find archive extraction sites where entry names flow into output file paths without containment checks), **batched verify** (taint + path-resolution analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file and write canonical JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it does not.

---

## What is Zip Slip

Zip Slip is an arbitrary file write vulnerability triggered during archive extraction. When an archive is extracted, each entry's name is used to construct the destination path on disk. If a malicious archive contains entry names that include path traversal sequences (e.g., `../../etc/cron.d/backdoor`, `../app/templates/evil.html`), and the application concatenates the extraction root with the entry name without first resolving the canonical path and verifying it stays inside the root, the entry will be written outside the intended directory.

The core pattern: *archive entry name, which is fully attacker-controlled when the archive source is user-supplied, reaches a filesystem write call without a canonicalize-then-assert-prefix check.*

Consequences range from overwriting application config files (privilege escalation, RCE via interpreted configs, service restart backdoors) to overwriting cron jobs, SSH authorized_keys, or web-served files. The severity is **critical** when the write path can reach executable or config-controlled locations.

### What Zip Slip IS

- Calling `zipfile.ZipFile.extract(member, path)` or `extractall(path)` in Python when `member` / the names in the archive are not individually validated before the call.
- Using `tarfile.TarFile.extract` or `extractall` in Python on an untrusted archive without pre-filtering names.
- Java: constructing a destination `File` with `new File(destDir, entry.getName())` and then calling `new FileOutputStream(dest)` without checking `dest.getCanonicalPath().startsWith(destDir.getCanonicalPath())`.
- Go: `os.Create(filepath.Join(dest, f.Name))` (or `os.OpenFile`) where `f.Name` comes directly from the archive entry without `filepath.Clean` plus a `strings.HasPrefix(abs, dest)` assertion.
- Node.js: `fs.createWriteStream(path.join(dest, entry.path))` where `entry.path` comes from `unzipper`, `adm-zip`, `extract-zip`, `tar`, `node-tar`, or similar libraries without first stripping traversal sequences.
- .NET: `Path.Combine(dest, entry.FullName)` in `ZipArchiveEntry` extraction loops without calling `Path.GetFullPath` and asserting the result starts with the canonical dest.
- Ruby: `File.join(dest, entry.name)` in a `Zip::File.open` block without `File.expand_path` containment.
- Any language/framework where the archive source is a user upload, URL fetch, or otherwise attacker-controlled AND entry names reach a write path.

### What Zip Slip is NOT

Do not flag these as Zip Slip:

- **Read-only inspection**: Opening an archive to list or read entries without writing them to disk (e.g., reading a ZIP in memory, parsing a JAR manifest without extraction). No write path = no Zip Slip.
- **Sandboxed ephemeral temp directories immediately deleted**: If extraction lands in a temp directory that is created with `mkdtemp`, never read back, and deleted before returning, and the OS enforces permissions that prevent privilege escalation from that path, the write may be out of scope. Still flag if the temp path is within the web root or a cron-watched directory.
- **Library-enforced containment**: Extraction via `zipfile.Path` (Python 3.12+), Apache Commons Compress with `ZipFile.getInputStream` + application-level guard, or any library that provably strips traversal before writing. Confirm the library actually prevents it — many do not.
- **Entry names filtered before extraction**: A `for member in zip.namelist()` loop that asserts `not os.path.isabs(member) and '..' not in member.split('/')` before calling `extract(member, dest)` is the correct fix and is NOT vulnerable.
- **Attacker cannot control the archive**: If the archive is generated server-side from known-good data (e.g., a build artifact assembled by the server itself) and never passes through user input, the risk is substantially lower — classify as `exploitability: unreachable`.

### Patterns That Prevent Zip Slip

When you see these patterns, the code is likely **not vulnerable**:

**1. Canonicalize-then-assert-prefix (the universal fix)**
```python
# Python — explicit containment check before each extract
import os, zipfile

def safe_extract(zip_path: str, dest: str) -> None:
    dest = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(dest, member))
            if not member_path.startswith(dest + os.sep):
                raise ValueError(f"Path traversal detected: {member}")
            zf.extract(member, dest)
```

```java
// Java — getCanonicalPath check
private void extractEntry(ZipEntry entry, String destDir) throws IOException {
    File destFile = new File(destDir, entry.getName());
    String canonicalDest = new File(destDir).getCanonicalPath();
    String canonicalEntry = destFile.getCanonicalPath();
    if (!canonicalEntry.startsWith(canonicalDest + File.separator)) {
        throw new SecurityException("Zip Slip: " + entry.getName());
    }
    // safe to write
}
```

```go
// Go — filepath.Clean + HasPrefix containment
func extractFile(dest string, f *zip.File) error {
    filePath := filepath.Join(dest, f.Name)
    filePath = filepath.Clean(filePath)
    if !strings.HasPrefix(filePath, filepath.Clean(dest)+string(os.PathSeparator)) {
        return fmt.Errorf("illegal file path: %s", filePath)
    }
    // safe to create
    return nil
}
```

```typescript
// Node.js — path.resolve + startsWith containment
import path from 'path';
import fs from 'fs';

function safeExtractPath(dest: string, entryPath: string): string {
    const resolved = path.resolve(dest, entryPath);
    if (!resolved.startsWith(path.resolve(dest) + path.sep)) {
        throw new Error(`Zip Slip: ${entryPath}`);
    }
    return resolved;
}
```

```csharp
// .NET — Path.GetFullPath containment
private static string GetSafeEntryPath(string dest, ZipArchiveEntry entry) {
    string fullDest = Path.GetFullPath(dest) + Path.DirectorySeparatorChar;
    string entryPath = Path.GetFullPath(Path.Combine(dest, entry.FullName));
    if (!entryPath.StartsWith(fullDest, StringComparison.Ordinal))
        throw new InvalidOperationException($"Zip Slip: {entry.FullName}");
    return entryPath;
}
```

```ruby
# Ruby — expand_path containment
Zip::File.open(zip_path) do |zip|
  zip.each do |entry|
    target = File.expand_path(entry.name, dest)
    raise "Zip Slip" unless target.start_with?(File.expand_path(dest) + File::SEPARATOR)
    FileUtils.mkdir_p(File.dirname(target))
    entry.extract(target)
  end
end
```

**2. Name-level pre-filtering (defense-in-depth, simpler but less robust)**
```python
# Reject names with traversal components before any extraction
for member in zf.namelist():
    parts = member.replace('\\', '/').split('/')
    if '..' in parts or any(os.path.isabs(p) for p in parts if p):
        raise ValueError(f"Dangerous entry: {member}")
    zf.extract(member, dest)
```

**3. Library with built-in containment**
```python
# zipfile.Path (Python 3.12+) — reads entries safely without writing traversal paths
# (for read-only inspection — still need explicit check when extracting to disk)
from zipfile import ZipFile, Path as ZipPath
root = ZipPath(ZipFile("archive.zip"))
for item in root.iterdir():
    # safe read; entry.name cannot escape the ZipPath object
    print(item.name)
```

---

## Vulnerable vs. Secure Examples

### Python — zipfile

```python
# VULNERABLE: extractall() without member name validation
import zipfile

def extract_upload(zip_path: str, dest_dir: str) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)          # ← any entry like ../../etc/cron.d/x is written there

# VULNERABLE: per-member extract without canonicalization
def extract_upload_v2(zip_path: str, dest_dir: str) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            zf.extract(member, dest_dir) # ← same: no containment check

# SECURE: canonicalize + assert prefix
import os

def extract_upload_safe(zip_path: str, dest_dir: str) -> None:
    dest_dir = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if not target.startswith(dest_dir + os.sep):
                raise ValueError(f"Zip Slip blocked: {member}")
            zf.extract(member, dest_dir)
```

### Python — tarfile

```python
# VULNERABLE: extractall on a user-supplied tar archive
import tarfile

def unpack_archive(tar_path: str, dest: str) -> None:
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)              # ← tar entries with ../.. in names escape dest

# ALSO VULNERABLE: filter= not set (Python 3.12 default is still 'fully_trusted')
with tarfile.open(tar_path) as tf:
    tf.extractall(dest, filter='fully_trusted')  # explicit, still unsafe

# SECURE: use filter='data' (Python 3.12+) — blocks device files and traversal
with tarfile.open(tar_path) as tf:
    tf.extractall(dest, filter='data')

# SECURE: manual guard for older Python
import tarfile, os

def safe_tar_extract(tar_path: str, dest: str) -> None:
    dest = os.path.realpath(dest)
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            target = os.path.realpath(os.path.join(dest, member.name))
            if not target.startswith(dest + os.sep):
                raise ValueError(f"Zip Slip blocked: {member.name}")
        tf.extractall(dest)
```

### Java — java.util.zip

```java
// VULNERABLE: entry.getName() concatenated without canonical check
import java.util.zip.*;
import java.io.*;

public class ZipExtractor {
    public void extract(File zipFile, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // VULNERABLE: no canonical path check
                File dest = new File(destDir, entry.getName());
                try (FileOutputStream fos = new FileOutputStream(dest)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}

// SECURE: canonicalize before writing
public class SafeZipExtractor {
    public void extract(File zipFile, File destDir) throws IOException {
        String canonicalDest = destDir.getCanonicalPath();
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File dest = new File(destDir, entry.getName());
                if (!dest.getCanonicalPath().startsWith(canonicalDest + File.separator)) {
                    throw new SecurityException("Zip Slip: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    dest.mkdirs();
                } else {
                    dest.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(dest)) {
                        zis.transferTo(fos);
                    }
                }
            }
        }
    }
}
```

### Java — Apache Commons Compress

```java
// VULNERABLE: using getName() directly in path construction
import org.apache.commons.compress.archivers.zip.*;

public void extractCommons(File zipFile, File destDir) throws IOException {
    try (ZipFile zf = new ZipFile(zipFile)) {
        Enumeration<ZipArchiveEntry> entries = zf.getEntries();
        while (entries.hasMoreElements()) {
            ZipArchiveEntry entry = entries.nextElement();
            File outFile = new File(destDir, entry.getName());   // VULNERABLE
            try (InputStream is = zf.getInputStream(entry);
                 FileOutputStream fos = new FileOutputStream(outFile)) {
                is.transferTo(fos);
            }
        }
    }
}
```

### Go — archive/zip

```go
// VULNERABLE: filepath.Join without containment check
import (
    "archive/zip"
    "io"
    "os"
    "path/filepath"
)

func extractZip(src, dest string) error {
    r, _ := zip.OpenReader(src)
    defer r.Close()
    for _, f := range r.File {
        // VULNERABLE: f.Name can be ../../etc/passwd
        path := filepath.Join(dest, f.Name)
        out, _ := os.Create(path)
        rc, _ := f.Open()
        io.Copy(out, rc)
        rc.Close()
        out.Close()
    }
    return nil
}

// SECURE: Clean + HasPrefix assertion
import (
    "fmt"
    "strings"
)

func safeExtractZip(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer r.Close()
    destAbs := filepath.Clean(dest) + string(os.PathSeparator)
    for _, f := range r.File {
        filePath := filepath.Clean(filepath.Join(dest, f.Name))
        if !strings.HasPrefix(filePath, destAbs) {
            return fmt.Errorf("zip slip blocked: %s", f.Name)
        }
        if f.FileInfo().IsDir() {
            os.MkdirAll(filePath, f.Mode())
            continue
        }
        if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
            return err
        }
        out, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil {
            return err
        }
        rc, _ := f.Open()
        io.Copy(out, rc)
        rc.Close()
        out.Close()
    }
    return nil
}
```

### Node.js — unzipper / adm-zip

```javascript
// VULNERABLE: unzipper — entry.path flows directly into createWriteStream
const unzipper = require('unzipper');
const path = require('path');
const fs = require('fs');

async function extractZip(zipPath, dest) {
    const zip = fs.createReadStream(zipPath).pipe(unzipper.Parse());
    for await (const entry of zip) {
        const outPath = path.join(dest, entry.path); // VULNERABLE: no traversal check
        entry.pipe(fs.createWriteStream(outPath));
    }
}

// VULNERABLE: adm-zip — extractAllTo passes entry names directly to the FS
const AdmZip = require('adm-zip');

function extractAdmZip(zipPath, dest) {
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(dest, true); // VULNERABLE if archive is attacker-controlled
}

// SECURE: resolve + assert before writing
const path = require('path');
const fs = require('fs');
const unzipper = require('unzipper');

async function safeExtract(zipPath, dest) {
    const resolvedDest = path.resolve(dest) + path.sep;
    const zip = fs.createReadStream(zipPath).pipe(unzipper.Parse());
    for await (const entry of zip) {
        const outPath = path.resolve(path.join(dest, entry.path));
        if (!outPath.startsWith(resolvedDest)) {
            entry.autodrain();
            throw new Error(`Zip Slip blocked: ${entry.path}`);
        }
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        entry.pipe(fs.createWriteStream(outPath));
    }
}
```

### .NET — System.IO.Compression

```csharp
// VULNERABLE: Path.Combine without GetFullPath containment check
using System.IO.Compression;

public static void ExtractZip(string zipPath, string dest) {
    using var archive = ZipFile.OpenRead(zipPath);
    foreach (var entry in archive.Entries) {
        // VULNERABLE: FullName can be ../../../Windows/System32/evil.dll
        string outPath = Path.Combine(dest, entry.FullName);
        Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
        entry.ExtractToFile(outPath, overwrite: true);
    }
}

// SECURE: Path.GetFullPath + StartsWith
public static void SafeExtractZip(string zipPath, string dest) {
    string fullDest = Path.GetFullPath(dest) + Path.DirectorySeparatorChar;
    using var archive = ZipFile.OpenRead(zipPath);
    foreach (var entry in archive.Entries) {
        string fullPath = Path.GetFullPath(Path.Combine(dest, entry.FullName));
        if (!fullPath.StartsWith(fullDest, StringComparison.Ordinal))
            throw new InvalidOperationException($"Zip Slip: {entry.FullName}");
        if (entry.FullName.EndsWith('/')) {
            Directory.CreateDirectory(fullPath);
        } else {
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            entry.ExtractToFile(fullPath, overwrite: true);
        }
    }
}
```

### Ruby — rubyzip

```ruby
# VULNERABLE: entry.name used directly in File.join without expand_path containment
require 'zip'

def extract_zip(zip_path, dest)
  Zip::File.open(zip_path) do |zip|
    zip.each do |entry|
      target = File.join(dest, entry.name)  # VULNERABLE
      FileUtils.mkdir_p(File.dirname(target))
      entry.extract(target) { true }        # overwrite: true
    end
  end
end

# SECURE: expand_path + start_with? containment
def safe_extract_zip(zip_path, dest)
  abs_dest = File.expand_path(dest) + File::SEPARATOR
  Zip::File.open(zip_path) do |zip|
    zip.each do |entry|
      target = File.expand_path(File.join(dest, entry.name))
      raise "Zip Slip: #{entry.name}" unless target.start_with?(abs_dest)
      FileUtils.mkdir_p(File.dirname(target))
      entry.extract(target) { true }
    end
  end
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Archive Extraction Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where an archive is extracted to disk in a way that could allow a Zip Slip / path traversal write — that is, where an archive entry name (or a path derived from it) reaches a filesystem write call without a provable canonicalize-then-assert-prefix containment check. Write results to `sast/zipslip-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, any file upload or archive-processing endpoints, and relevant library choices.
>
> **What to search for — archive extraction sinks**:
>
> Look for archive extraction calls where the resulting output path on disk is influenced by the archive entry name without a clear containment check immediately before the write. Flag sites where you see any archive entry name variable flowing into a file creation or write call.
>
> 1. **Python — zipfile**:
>    - `ZipFile.extractall(path)` — always flag if the archive can come from user input
>    - `ZipFile.extract(member, path)` — flag unless `member` is validated before the call
>    - Search: `extractall`, `zf.extract(`, `zipfile.ZipFile`
>
> 2. **Python — tarfile**:
>    - `TarFile.extractall(path)` — always flag; `filter='data'` is the safe form (Python 3.12+)
>    - `TarFile.extract(member, path)` — flag unless member path is canonicalized
>    - Search: `tarfile.open`, `tf.extractall`, `tf.extract(`
>
> 3. **Java**:
>    - `entry.getName()` used in `new File(destDir, entry.getName())` or string concat leading to `new FileOutputStream(...)`, `Files.copy(...)`, `Files.write(...)`
>    - `getCanonicalPath()` checked after construction is the mitigation — if absent, flag
>    - `ZipEntry`, `ZipInputStream`, `ZipFile`, `ZipArchiveEntry` (Commons Compress)
>    - Search: `entry.getName()`, `ZipInputStream`, `ZipFile`, `ZipArchiveEntry`, `TarArchiveEntry`
>
> 4. **Go**:
>    - `filepath.Join(dest, f.Name)` or `path.Join(dest, f.Name)` used in `os.Create`, `os.OpenFile`, `ioutil.WriteFile`
>    - Mitigation: `filepath.Clean` + `strings.HasPrefix(abs, destAbs)` — flag if absent
>    - Search: `archive/zip`, `archive/tar`, `f.Name`, `filepath.Join`, `os.Create`
>
> 5. **Node.js**:
>    - `entry.path` or `entry.fileName` in `fs.createWriteStream(path.join(dest, ...))` — flag unless `path.resolve` + `startsWith` guard present
>    - `zip.extractAllTo(dest)` in `adm-zip` — flag if archive is user-supplied
>    - `extract(src, { dir: dest })` in `extract-zip` — safe by default since v2 when dest is absolute; still flag for review if archive is user-supplied and version unknown
>    - Search: `unzipper`, `adm-zip`, `AdmZip`, `extract-zip`, `node-tar`, `tar.x(`, `entry.path`, `entry.fileName`
>
> 6. **.NET**:
>    - `entry.FullName` in `Path.Combine(dest, entry.FullName)` followed by `entry.ExtractToFile(...)` or `File.Create(...)` — flag unless `Path.GetFullPath` + `StartsWith` present
>    - `ZipFile.ExtractToDirectory(zipPath, dest)` — safer in .NET 5+ but still flag if framework version unknown
>    - Search: `ZipArchiveEntry`, `entry.FullName`, `ExtractToFile`, `ZipFile.OpenRead`
>
> 7. **Ruby**:
>    - `File.join(dest, entry.name)` in a `Zip::File.open` or `Zip::InputStream` block — flag unless `File.expand_path` + `start_with?` present
>    - Search: `rubyzip`, `Zip::File`, `entry.name`, `entry.extract`
>
> 8. **Cross-cutting — shell invocations**:
>    - Shell commands that unzip or untar user-supplied files: `system("unzip #{zip_path} -d #{dest}")`, `Process.Start("tar", $"xf {tarPath} -C {dest}")` — flag for manual review; shell tools themselves do not prevent traversal unless `-P` strip-components flags are used carefully
>    - Search: `unzip`, `tar x`, `7z x`, `jar xf` in shell invocations with user-controlled paths
>
> **What to skip** (safe patterns — do not flag):
> - Read-only entry inspection without writing to disk (`zf.read(member)`, `entry.read()`, `zis.getInputStream(entry)` without a `FileOutputStream`)
> - `extractall` / `extract` calls where every entry name is validated through a function that checks both `os.path.isabs` and `'..'` membership **and** that function is directly called in a loop before each write
> - `Path.GetFullPath` + `StartsWith` present immediately before every `ExtractToFile` call — confirmed safe
> - Archives generated entirely server-side from known-good data with no user input in the entry names
>
> **Output format** — write to `sast/zipslip-recon.md`:
>
> ```markdown
> # Zip Slip Recon: [Project Name]
>
> ## Summary
> Found [N] archive extraction sites that may be vulnerable to Zip Slip.
>
> ## Extraction Sites
>
> ### 1. [Descriptive name — e.g., "extractall in upload handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Archive format**: [zip / tar / jar / 7z / cpio]
> - **Library / API**: [zipfile / tarfile / ZipInputStream / unzipper / ZipArchiveEntry / Zip::File]
> - **Extraction call**: [extractall / extract / ExtractToFile / os.Create / createWriteStream / etc.]
> - **Entry name variable**: [the variable used in the path — e.g., `entry.getName()`, `f.Name`, `entry.path`]
> - **Containment check present**: [Yes / No / Partial — describe what is or is not there]
> - **Archive source**: [user upload / URL fetch / server-generated / unknown]
> - **Code snippet**:
>   ```
>   [the extraction loop or call, showing entry name → path construction → write]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/zipslip-recon.md`. If the recon found **zero extraction sites** (the summary reports "Found 0" or the "Extraction Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following to `sast/zipslip-results.md`, write `{"findings":[]}` to `sast/zipslip-results.json`, and stop:

```markdown
# Zip Slip Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one extraction site.

### Phase 2: Verify — Taint and Containment Analysis (Batched)

After Phase 1 completes, read `sast/zipslip-recon.md` and split the extraction sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent performs taint and containment analysis only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/zipslip-recon.md` and count the numbered site sections under "Extraction Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/zipslip-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include those selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned archive extraction site, determine whether the site is exploitable as a Zip Slip vulnerability. Answer three questions: (1) Is the archive source user-controlled? (2) Is the entry name used to construct a write path without a canonicalize-then-assert-prefix check? (3) Where would a malicious entry land — is the write target a privileged or impactful location? Write results to `sast/zipslip-batch-[N].md`.
>
> **Your assigned extraction sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the upload surface, processing pipelines, and filesystem layout.
>
> **Zip Slip verify questions — answer all three for each site**:
>
> **Question 1: Is the archive source user-controlled?**
>
> Trace backwards from the extraction call to the archive file or stream's origin:
>
> - **Directly user-supplied**: The archive comes from an HTTP multipart upload (`request.FILES`, `req.file`, `@RequestPart`, `IFormFile`), a URL provided by the user and fetched server-side, an S3/blob object name supplied by the user, or any other untrusted external input.
> - **Indirectly user-supplied**: The archive was written to a path that the user influenced, or was generated by processing user-supplied data (e.g., the user provides the filenames that end up inside the archive). Even if the archive was assembled server-side, if its entry names are derived from user input, the entry names are user-controlled.
> - **Partially trusted**: The archive comes from an authenticated internal system, a partner API, or a pre-validated source. Lower exploitability but still a risk if the trusted source is compromisable.
> - **Server-controlled**: The archive is generated entirely by the server from known-good data (e.g., a backup of application-managed files with server-assigned names). Not user-controlled — lower risk, flag as `exploitability: unreachable` unless there is a secondary injection path.
>
> **Question 2: Is there a provable containment check?**
>
> Read the extraction code and any helper functions it calls. Look for the full canonicalize-then-assert pattern:
>
> - **Python**: `os.path.realpath(os.path.join(dest, member))` followed by `target.startswith(dest + os.sep)` — both steps required. `os.path.normpath` is NOT equivalent to `realpath` (it does not resolve symlinks). `'..' not in member.split('/')` is defense-in-depth but incomplete (Windows paths, URL-encoded sequences).
> - **Java**: `new File(destDir, entry.getName()).getCanonicalPath().startsWith(new File(destDir).getCanonicalPath() + File.separator)` — both `getCanonicalPath()` calls required. `getAbsolutePath()` is NOT equivalent (does not resolve `..` links).
> - **Go**: `filepath.Clean(filepath.Join(dest, f.Name))` followed by `strings.HasPrefix(clean, filepath.Clean(dest)+string(os.PathSeparator))` — both required. `filepath.Join` alone does not prevent traversal.
> - **Node.js**: `path.resolve(path.join(dest, entry.path))` followed by `.startsWith(path.resolve(dest) + path.sep)` — both required. `path.normalize` is NOT equivalent to `path.resolve`.
> - **.NET**: `Path.GetFullPath(Path.Combine(dest, entry.FullName)).StartsWith(Path.GetFullPath(dest) + Path.DirectorySeparatorChar, StringComparison.Ordinal)` — both required.
> - **Ruby**: `File.expand_path(File.join(dest, entry.name)).start_with?(File.expand_path(dest) + File::SEPARATOR)` — both required.
>
> If the check is absent, partial, or uses a weaker form (normalize instead of canonicalize, string reject instead of canonical assertion), classify as Vulnerable or Likely Vulnerable.
>
> **Question 3: What is the impact if exploited?**
>
> Given the extraction root (e.g., `uploads/`, `/tmp/extracted/`, `/var/www/app/`) and a relative traversal path like `../../etc/cron.d/x`, determine where the file lands:
>
> - **Critical**: Write reaches `/etc/cron.d/`, `/etc/cron.hourly/`, `~/.ssh/authorized_keys`, the web server document root (executable PHP/JSP/ASP files), a service configuration file that is auto-loaded, or any other location that enables immediate RCE or privilege escalation.
> - **High**: Write reaches the application directory (overwriting Python/Ruby/Node source files, `requirements.txt`, templates that get server-side rendered) but not directly executable system locations.
> - **Medium**: Write reaches a temp directory with restricted execution, a queue directory, or a log directory — harmful (log poisoning, data corruption) but not direct RCE.
> - **Low**: Write reaches an isolated sandbox with no outbound impact or is immediately cleaned up.
>
> **FP-killers — reasons to downgrade or dismiss**:
>
> - The containment check IS present and correct — classify as Not Vulnerable.
> - The archive source is provably server-generated from known-safe names — `exploitability: unreachable`.
> - The extraction root is a sandboxed directory mounted noexec with no write-through to privileged paths — lower severity.
> - The library has changed to include built-in containment in the version the project uses (verify with `package.json`, `requirements.txt`, `pom.xml`, `go.mod`) — check release notes before dismissing.
>
> **Setting severity and exploitability**:
>
> | Condition | Severity | Exploitability |
> |---|---|---|
> | User-supplied archive, no containment check, write reaches cron/ssh/web root | critical | reachable |
> | User-supplied archive, no containment check, write reaches app directory | high | reachable |
> | User-supplied archive, weak check (normalize not canonicalize), write reaches privileged path | high | conditional |
> | Partially trusted archive source, no check, privileged write path | high | conditional |
> | User-supplied archive, no check, write reaches temp/log only | medium | reachable |
> | Server-generated archive, no check, privileged write path | medium | conditional |
> | Server-generated archive, no check, temp/restricted path | low | unreachable |
> | Any source, correct canonicalize+assert check present | — | unreachable (not a finding) |
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User-controlled archive entry name reaches a write path with no effective containment check, confirmed by tracing the archive source and the code path.
> - **Likely Vulnerable**: Archive source is probably user-controlled or containment check is present but incomplete/incorrect; requires confirmation.
> - **Not Vulnerable**: Canonicalize-then-assert-prefix present and correct, OR archive source is provably server-controlled with no user influence on entry names.
> - **Needs Manual Review**: Cannot determine archive source or whether the containment check covers all code paths with confidence.
>
> **Output format** — write to `sast/zipslip-batch-[N].md`:
>
> ```markdown
> # Zip Slip Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Archive format**: [zip / tar / jar / 7z]
> - **Archive source**: [user upload via POST /upload / URL fetch from user-supplied URL / etc.]
> - **Issue**: [e.g., "extractall() called on user-uploaded ZIP with no member name validation; entry ../../etc/cron.d/x would be written to /etc/cron.d/x"]
> - **Taint trace**:
>   1. [User uploads file via POST /api/import → stored as `tmp_path`]
>   2. [`extract_archive(tmp_path, dest="/var/app/uploads")` called]
>   3. [`zipfile.ZipFile(tmp_path).extractall(dest)` — no member filtering]
>   4. [Entry `../../etc/cron.d/backdoor` written to `/etc/cron.d/backdoor`]
> - **Impact**: [e.g., "Attacker can write a cron job that executes arbitrary commands as the app's service user, achieving persistent RCE"]
> - **Containment check**: [None / Partial — describe]
> - **Severity**: critical
> - **Exploitability**: reachable
> - **Confidence**: high
> - **Remediation**: [e.g., "Replace extractall() with a per-member loop that calls os.path.realpath(os.path.join(dest, member)) and asserts the result starts with os.path.realpath(dest) + os.sep before each extract call. Alternatively use tarfile filter='data' (Python 3.12+)."]
> - **Proof-of-concept**:
>   ```python
>   # Create a malicious ZIP with a traversal entry
>   import zipfile, os
>   with zipfile.ZipFile("evil.zip", "w") as zf:
>       zf.writestr("../../etc/cron.d/backdoor", "* * * * * root id > /tmp/pwned\n")
>   # Then upload evil.zip to POST /api/import
>   ```
> - **chain_id**: path-write-rce
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Archive format**: [format]
> - **Archive source**: [describe; note uncertainty]
> - **Issue**: [e.g., "Containment check uses os.path.normpath instead of os.path.realpath — symlink-based traversal remains possible"]
> - **Taint trace**: [best-effort trace; mark uncertain steps]
> - **Concern**: [Why the partial check is insufficient]
> - **Severity**: high
> - **Exploitability**: conditional
> - **Confidence**: medium
> - **Remediation**: [Replace normpath with realpath; ensure the startswith guard uses os.sep suffix]
> - **chain_id**: path-write-rce
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Extraction loop calls realpath() and asserts prefix before each write" / "Archive is server-generated from application-managed filenames"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [e.g., "Cannot trace archive origin — it is received from an opaque internal service; entry name validation happens in a shared utility not visible in this repo"]
> - **Suggestion**: [Trace the archive source to its entry point; review the shared utility's source]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/zipslip-batch-*.md` file and merge them. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/zipslip-batch-1.md`, `sast/zipslip-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/zipslip-results.md`:

```markdown
# Zip Slip Analysis Results: [Project Name]

## Executive Summary
- Extraction sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable findings to `sast/zipslip-results.json` using the schema below. Assign a sequential `id` of the form `zipslip-1`, `zipslip-2`, etc., to each confirmed finding (Vulnerable and Likely Vulnerable only; exclude NOT VULNERABLE). If there are no confirmed findings, write `{"findings":[]}`.

```json
{
  "findings": [
    {
      "id": "zipslip-1",
      "skill": "sast-zipslip",
      "severity": "critical",
      "title": "Zip Slip in archive upload handler — extractall() without member validation",
      "description": "User-uploaded ZIP processed with zipfile.ZipFile.extractall(dest) in src/upload.py. Entry names are not validated before extraction; a crafted archive with entry '../../etc/cron.d/backdoor' writes outside the extraction root, enabling persistent RCE as the service user.",
      "location": { "file": "src/upload.py", "line": 42, "column": 8 },
      "remediation": "Replace extractall() with a per-member loop. For each member call os.path.realpath(os.path.join(dest, member)) and assert the result starts with os.path.realpath(dest) + os.sep before calling extract(member, dest). On Python 3.12+, use tarfile.extractall(filter='data') for tar archives.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "path-write-rce"
    }
  ]
}
```

6. After writing both output files, **delete all intermediate files**: `sast/zipslip-recon.md` and all `sast/zipslip-batch-*.md`.

---

## chain_id Values

The following `chain_id` strings are defined for findings from this skill. Use them exactly as shown so the triage and report skills can join related findings across skills.

| chain_id | Meaning |
|---|---|
| `path-write-rce` | Zip Slip write + path traversal chain: archive entry name escapes extraction root → arbitrary file write → config/script overwrite → RCE. Links to `sast-pathtraversal` findings in the same attack path. |
| `zipslip-rce` | Direct Zip Slip to RCE chain: archive entry name writes to a directly executable location (cron job, web-served script, init.d service file) → immediate code execution. Links to `sast-rce` findings. |

Set `chain_id: null` for findings that do not participate in a cross-skill chain (e.g., write to an isolated temp directory with no downstream impact).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 extraction sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any archive extraction call where an entry name or entry-derived variable reaches a write path without an obvious containment check. Do not deeply trace the archive source in Phase 1 — that is Phase 2's job.
- **Phase 2 answers three questions for each site**: (1) Is the archive source user-controlled? (2) Is there a correct canonicalize-then-assert-prefix check? (3) Where does the write land if traversal succeeds?
- `os.path.normpath` and `filepath.Clean` alone are insufficient — they handle `..` syntactically but do not resolve symlinks. Only `os.path.realpath`, `File.getCanonicalPath()`, and `Path.GetFullPath()` give true canonical paths. Flag uses of normalize-only as "Likely Vulnerable".
- The trailing separator in the prefix assertion (`dest + os.sep`, `canonicalDest + File.separator`) is not optional. Without it, a dest of `/tmp/extract` would incorrectly allow writes to `/tmp/extract-evil/`. Always check for the separator.
- Windows vs. Unix: on Windows, paths use `\` as separator; `Path.DirectorySeparatorChar`, `File.separator`, and `os.sep` are the correct constants. Platform-specific traversal using `\` may bypass Unix-only checks. Flag mixed-separator handling.
- Symlink escape: even with a name-level check rejecting `..`, an attacker can use symlinks inside the archive to escape the extraction root (a symlink entry pointing to `../` followed by a file entry written through it). Only `realpath`/`getCanonicalPath`/`GetFullPath` defend against this.
- `ZipFile.ExtractToDirectory` (.NET 5+) is safer but not bulletproof in all versions — flag for version verification if the project's target framework is below .NET 5.
- `extract-zip` (Node.js) >= 2.0.0 performs containment checking by default when `dir` is an absolute path — still flag for review and version verification.
- `tarfile.extractall(filter='data')` (Python 3.12+) blocks device files, setuid bits, and path traversal — this is the recommended fix for tar extraction. Flag uses without `filter=` or with `filter='fully_trusted'`.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives (missed Zip Slip) lead to RCE; false positives cost one code review comment.
- Always emit `sast/zipslip-results.json` with `"findings": []` even when no vulnerabilities are found, so the `sast-skills export` aggregator can verify the scan ran.
- Clean up intermediate files: delete `sast/zipslip-recon.md` and all `sast/zipslip-batch-*.md` after the final results files are written.
