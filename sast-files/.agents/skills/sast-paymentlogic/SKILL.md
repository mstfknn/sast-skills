---
name: sast-paymentlogic
description: >-
  Detect payment and monetary business-logic vulnerabilities using a three-phase
  approach: recon (locate checkout, refund, coupon, balance, and pricing handlers),
  batched verify (parallel subagents, 3 candidates each, semantic taint analysis
  from client input to monetary outcome), and merge (consolidate into
  sast/paymentlogic-results.md and sast/paymentlogic-results.json). Scope boundary:
  monetary/payment abuse only — price and quantity manipulation, coupon and wallet
  stacking, refund fraud, negative-amount injection, and race conditions on monetary
  balances or inventory. General access-control flaws belong in sast-missingauth;
  non-monetary race conditions belong in sast-race. Requires sast/architecture.md
  (run sast-analysis first). Use when asked to find payment fraud, price manipulation,
  checkout abuse, or financial business-logic bugs.
version: 0.1.0
---

# Payment Logic Vulnerability Detection

You are performing a focused security assessment to find monetary and payment business-logic vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (locate every handler that computes a monetary total, applies a discount, processes a refund, or debits/credits a balance), **batched verify** (determine whether each candidate is exploitable in parallel batches of 3), and **merge** (consolidate batch results into a unified report and canonical JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

**Scope boundary**: This skill covers monetary and payment abuse only. Do not flag here:

- General access-control gaps (missing login on an endpoint) → `sast-missingauth`
- Non-monetary race conditions (concurrent write to a non-financial resource) → `sast-race`
- General business-logic flaws unrelated to money (rating out of range, workflow step skip) → `sast-businesslogic`
- Technical injection flaws (SQLi, XSS, RCE) → dedicated injection skills
- Pure UI/client-side validation with no monetary consequence server-side

---

## What Are Payment Logic Vulnerabilities

Payment logic vulnerabilities arise when a monetary computation, discount application, refund calculation, or balance update can be manipulated by crafting request fields — without exploiting a technical flaw like injection. The attacker sends syntactically valid HTTP requests but with values the developer never intended the server to trust.

The core pattern: *client-supplied input (price, quantity, coupon code, refund amount, transfer amount) flows into a monetary computation or database debit/credit without the server re-deriving the authoritative value from its own records.*

### What Payment Logic Vulnerabilities ARE

- `total = request.json["unit_price"] * request.json["quantity"]` — price trusted from the request body, never re-fetched from the products table
- Accepting `quantity: -5` on a purchase endpoint, causing a credit instead of a charge
- A coupon applied in two concurrent requests because the single-use check and the insert are not atomic
- A refund endpoint that accepts `amount: 9999` from the client without capping it to the original charge amount
- `SELECT balance FROM wallets WHERE id=? UPDATE wallets SET balance=balance-? WHERE id=?` without `SELECT … FOR UPDATE`, enabling a double-spend race
- A discount code that can stack with itself because there is no per-order uniqueness constraint
- A negative transfer amount (`amount: -100`) that moves money from recipient to sender
- Floating-point precision abuse across many micro-transactions to accumulate unbounded credit
- `max_credit_balance` never checked before crediting a promotional wallet

### What Payment Logic Vulnerabilities Are NOT

Do not flag these as payment logic issues:

- **SQL injection on a payment endpoint**: That is a technical injection flaw — `sast-sqli`
- **Missing authentication on `/checkout`**: That is unauthenticated access — `sast-missingauth`
- **IDOR on order IDs**: Accessing another user's order — a separate access-control class
- **Non-monetary race on user profile**: Concurrent write to a non-financial field — `sast-race`
- **Price validation that exists only in the frontend form**: Flag only if there is also no server-side check

---

## Payment Logic Vulnerability Categories

Use these categories during recon to prioritize handlers. Verify each category that is applicable to the codebase being assessed.

### 1. Client-Supplied Price / Amount Trusted by Server

The server reads `unit_price`, `amount`, `total`, or `price` from the request body and uses it directly in a charge, invoice, or ledger entry without re-fetching the authoritative value from a products, price-list, or plan table.

- Mass assignment of a price field onto an ORM model (`Order(**request.json)`) when `price` is in the model's allowed attributes
- Currency / unit confusion (cents vs dollars) when the client can supply the unit
- Floating-point arithmetic on currency without rounding to the minor unit before charging

### 2. Quantity and Numeric Limit Violations

- Negative quantities (`quantity: -1`) producing a credit instead of a debit
- Zero quantities bypassing a minimum-purchase constraint
- Quantities exceeding a per-user or per-order cap enforced only client-side
- Integer overflow/underflow in a quantity or balance field stored as a 32-bit integer

### 3. Coupon, Promo, and Discount Stacking Abuse

- A coupon marked as single-use but the redemption check and the mark-as-used write are not in the same database transaction, enabling a TOCTOU race
- No per-user or per-order uniqueness constraint on coupon application (same code applied twice to the same order)
- Stacking multiple coupon types that were not designed to combine (e.g., a percentage discount stacked with a flat discount that reduces the total below zero)
- Using an expired coupon when expiry is only checked client-side or not checked at all
- Discount reducing the total below zero with no floor at 0.00

### 4. Refund and Credit Fraud

- Refund endpoint reads `amount` from the client and credits that amount without capping to the original charge from the payment record
- Partial refund logic that allows re-requesting a refund on an already-refunded line item (double refund)
- Promotional credit applied without checking a `max_credit_balance` cap
- Refund possible after the digital good has been consumed (no `consumed_at` check)

### 5. Negative-Amount Injection

- A transfer or payment endpoint accepts a negative `amount` value, sending money in the opposite direction
- No `amount > 0` guard before calling the payment gateway or writing a ledger entry
- Discount of `amount: -50` effectively adding to the total and creating an over-payment that is then refunded at a profit

### 6. Race Conditions on Monetary Balances and Inventory

- `SELECT balance … UPDATE balance` without `SELECT … FOR UPDATE` (MySQL / PostgreSQL) or optimistic locking (`WHERE balance >= :amount AND version = :v`)
- Two concurrent refund requests for the same order both passing the `status != refunded` check before either commits the status change
- Inventory reservation: `if item.stock > 0: item.stock -= quantity` without a database transaction or atomic decrement, allowing overselling
- Loyalty point / wallet credit race: two concurrent requests both read the same balance and both write back `balance + reward`

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Locate Payment and Monetary Handlers

Launch a subagent with the following instructions:

> **Goal**: Identify every location in the codebase that computes a monetary total, applies a discount or coupon, processes a refund or credit, or debits/credits a balance. Write results to `sast/paymentlogic-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the payment stack, ORM, and currency handling approach.
>
> **Step 1 — Identify the payment surface**:
>
> Read `sast/architecture.md` and explore the codebase to discover:
> - What payment or checkout features exist? (stripe integration, in-app wallet, subscription billing, invoice generation, point-of-sale)
> - What monetary models / entities exist? (Order, Payment, Transaction, Wallet, Invoice, Subscription, CreditBalance, Coupon, Discount, Refund, Ledger)
> - What field names are associated with monetary values? (`price`, `amount`, `total`, `unit_price`, `quantity`, `balance`, `credit`, `discount_amount`, `refund_amount`, `transfer_amount`)
> - What discount or coupon features exist? (promo codes, referral bonuses, loyalty points, gift cards, volume discounts, percentage discounts)
> - What refund or chargeback flows exist? (partial refund, full refund, store credit instead of money back)
> - What balance operations exist? (wallet top-up, withdrawal, transfer, deduct, credit, rollback)
>
> **Step 2 — Locate candidate sinks**:
>
> Search the codebase for each pattern group in the table below. For each match, record the file path, line range, and which pattern it matches.
>
> | Pattern group | Search terms / patterns |
> |---|---|
> | Price/amount from request | `request.json`, `request.body`, `req.body`, `request.data`, `request.form` combined with `price`, `unit_price`, `amount`, `total`, `cost` |
> | Quantity from request | `request.json`, `request.body`, `req.body` combined with `quantity`, `qty`, `count`, `units` |
> | Coupon/promo redemption | `coupon`, `promo`, `discount_code`, `voucher`, `referral_code`, `redeem`, `apply_coupon`, `use_coupon` |
> | Refund / credit | `refund`, `credit`, `chargeback`, `reverse`, `void`, `partial_refund`, `issue_credit` |
> | Balance debit/credit | `balance`, `wallet`, `ledger`, `debit`, `credit_balance`, `withdraw`, `transfer`, `top_up` |
> | Charge / payment gateway call | `charge`, `capture`, `create_payment_intent`, `stripe.charge`, `braintree.sale`, `paypal.order.capture`, `invoice.finalize` |
> | Inventory reservation | `stock`, `inventory`, `reserve`, `decrement_stock`, `available_quantity` |
> | Negative / zero guard | `> 0`, `>= 0`, `<= 0`, `negative`, `must be positive` — to identify where guards exist and where they are absent |
> | Locking | `SELECT … FOR UPDATE`, `with_for_update`, `optimistic`, `version`, `row_lock` — to identify where locking is used and where it is absent |
>
> **Step 3 — Group by risk tier**:
>
> After collecting matches, group them into:
> - **Tier 1 (High Risk)**: Client input directly in a monetary calculation — no intermediate DB lookup visible
> - **Tier 2 (Medium Risk)**: Coupon / refund handlers — need to check for atomicity and uniqueness constraints
> - **Tier 3 (Investigate)**: Balance operations — need to check for locking
> - **Tier 4 (Likely Safe)**: DB lookup of price present before computation
>
> **Output format** — write to `sast/paymentlogic-recon.md`:
>
> ```markdown
> # Payment Logic Recon: [Project Name]
>
> ## Payment Surface Summary
> [2–3 sentences: what payment/monetary features exist in this codebase]
>
> ## Models and Fields Identified
> - [Model]: [relevant monetary fields and their types]
>
> ## Candidates
>
> ### 1. [Short description, e.g. "Checkout total from request body"]
> - **File**: `path/to/file.ext` (lines X–Y)
> - **Pattern**: [Which pattern group this matches]
> - **Risk Tier**: [1 / 2 / 3 / 4]
> - **Snippet**: [3–5 line code excerpt showing the suspicious assignment or computation]
> - **Concern**: [One sentence: why this is suspicious]
>
> ### 2. ...
>
> [Use sequential numbering ### 1., ### 2., ... for all candidates — required for batching in Phase 2.]
>
> ## Pattern Groups Not Found
> [List any pattern groups from the table above that produced zero matches and why]
> ```

### Phase 2: Verify — Determine Exploitability (Batched)

After Phase 1 completes, read `sast/paymentlogic-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/paymentlogic-recon.md` and count the numbered candidate sections (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/paymentlogic-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate, determine whether client-supplied input reaches a monetary computation, discount application, refund calculation, or balance update without being validated or re-derived from authoritative server-side records. Write results to `sast/paymentlogic-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the ORM, transaction patterns, and where price/quantity authority lives.
>
> **What this skill does NOT flag** — skip these, they belong to other skills:
> - SQL injection, XSS, RCE, SSRF, XXE → injection skills
> - Endpoint requires no authentication at all → `sast-missingauth`
> - Non-monetary race condition (concurrent write to a non-financial resource) → `sast-race`
> - IDOR on order IDs → access-control class
>
> **For each candidate, answer the following verify questions**:
>
> **Q1 — Is the monetary value re-derived server-side?**
> - Does the code look up the price, discount amount, or refund cap from a database table (products, price_lists, charges, subscriptions) using the item/plan/charge ID?
> - Or does it use the value supplied directly in the request body, query string, or session variable set by the client?
> - If re-derived: is the lookup in the same request handler, before the computation? Or is it cached from a previous request (potentially stale)?
>
> **Q2 — Is the monetary amount validated as positive?**
> - Is there a server-side check `amount > 0` (or `quantity > 0`) before the value is used in a charge, transfer, or balance update?
> - Does the check happen on the raw request value or after a transformation that might change the sign?
> - Is there an upper-bound check (e.g., `amount <= original_charge.amount` for refunds)?
>
> **Q3 — Is coupon/discount uniqueness enforced atomically?**
> - Is there a database unique constraint on `(order_id, coupon_id)` or `(user_id, coupon_id)` that would prevent double application at the DB level?
> - If enforced in application code: is the check and the insert/update in the same database transaction (`BEGIN … COMMIT`) with a row-level lock (`SELECT … FOR UPDATE` on the coupon record)?
> - Is the coupon's `used_at` or `redeemed_by` field set atomically with the discount application?
> - Is the coupon expiry date checked at redemption time using the server's clock (not a client-supplied timestamp)?
>
> **Q4 — Is balance/inventory updated atomically?**
> - Are balance reads and writes in the same database transaction?
> - Is `SELECT … FOR UPDATE` or an equivalent row-level lock used on the balance/inventory row before the update?
> - Alternatively, is an optimistic locking pattern used: `UPDATE wallets SET balance = balance - :amount, version = version + 1 WHERE id = :id AND version = :expected_version AND balance >= :amount`?
> - Is the number of rows updated checked after the statement (a value of 0 rows updated means a concurrent modification won the race)?
>
> **Q5 — False-positive killers (always check before flagging)**:
>
> | False-positive condition | How to verify |
> |---|---|
> | Price re-fetched from DB | Look for `product = db.get(product_id)` / `Item.objects.get(pk=item_id)` before `total = product.price * qty` |
> | Coupon validated with unique index | Check migrations / schema for `UNIQUE (user_id, coupon_id)` or similar |
> | Refund capped to original charge | Look for `min(request_amount, charge.amount)` or `charge = Payment.get(charge_id); if amount > charge.amount: raise` |
> | Positive-amount guard in place | Look for `if amount <= 0: raise ValidationError` or Pydantic/Zod field with `gt=0` |
> | Atomic balance update | `UPDATE wallets SET balance = balance - %s WHERE id = %s AND balance >= %s` or `SELECT … FOR UPDATE` |
>
> **Classification**:
> - **Exploitable**: The monetary value is taken from client input with no server-side re-derivation or positive guard. A crafted request directly yields financial gain.
> - **Likely Exploitable**: A guard or re-derivation exists but has a gap — race window, missing edge case (zero allowed but negative not), bypassable condition.
> - **Not Exploitable**: Server-side re-derivation from authoritative records is in place, or atomic locking prevents the race.
> - **Needs Manual Review**: Cannot determine with confidence — complex multi-service call chain, external payment SDK re-validates, or the relevant ORM method needs runtime inspection.
>
> **Severity guidance**:
> - **critical**: Unbounded monetary gain possible (negative amount yields unlimited credit; no upper-bound on refund amount)
> - **high**: Direct financial loss or inventory manipulation on a reachable, unauthenticated or low-privilege path
> - **medium**: Monetary manipulation requires a privileged role, is rate-limited, or the gain is bounded by a soft limit
> - **low**: Theoretical numeric edge case with no realistic monetary impact
>
> **Output format** — write to `sast/paymentlogic-batch-[N].md`:
>
> ```markdown
> # Payment Logic Batch [N] Results
>
> ## Findings
>
> ### [EXPLOITABLE] Candidate title
> - **Category**: [e.g. Client-Supplied Price Trusted by Server]
> - **CWE**: CWE-840 (Business Logic Errors)
> - **File**: `path/to/file.ext` (lines X–Y)
> - **Endpoint**: `METHOD /path`
> - **Monetary Value at Risk**: [What can the attacker gain — free goods, unbounded credit, refund fraud, etc.]
> - **Taint Path**: [Request field name → function/variable → monetary operation; trace each step]
> - **Missing Control**: [What server-side check is absent or bypassable]
> - **Proof**:
>   ```
>   [Code excerpt showing the taint path, annotated with the missing guard]
>   ```
> - **Dynamic Test**:
>   ```
>   curl -s -X POST https://TARGET/api/checkout \
>     -H "Content-Type: application/json" \
>     -H "Authorization: Bearer <valid_token>" \
>     -d '{"item_id": 1, "unit_price": 0.01, "quantity": 1}'
>   # Expected: order created with total $0.01 (attacker-controlled price)
>   # Confirm: check created order total in response or DB
>   ```
> - **Severity**: [critical / high / medium / low]
> - **Exploitability**: [reachable / conditional / unreachable / unknown]
> - **Confidence**: [high / medium / low]
> - **Chain ID**: [payment-fraud-surface or null]
> - **Remediation**: [Specific fix, e.g. "Fetch product.price from the DB using item_id before computing total; never use the client-supplied price field"]
>
> ### [LIKELY EXPLOITABLE] Candidate title
> - **Category**: [e.g. Race Condition on Balance Update]
> - **CWE**: CWE-840 (Business Logic Errors)
> - **File**: `path/to/file.ext` (lines X–Y)
> - **Endpoint**: `METHOD /path`
> - **Monetary Value at Risk**: [What an attacker could achieve with the race]
> - **Taint Path**: [Sequence showing the TOCTOU window]
> - **Enforcement Gap**: [What partial protection exists and why it is insufficient]
> - **Proof**:
>   ```
>   [Code excerpt showing the unprotected read-modify-write sequence]
>   ```
> - **Dynamic Test**:
>   ```
>   # Send two concurrent requests to trigger the race
>   for i in 1 2; do
>     curl -s -X POST https://TARGET/api/wallet/withdraw \
>       -H "Authorization: Bearer <token>" \
>       -d '{"amount": 100}' &
>   done
>   wait
>   # Confirm: check wallet balance < 0 or two successful withdrawals when only one should succeed
>   ```
> - **Severity**: [critical / high / medium / low]
> - **Exploitability**: [reachable / conditional / unreachable / unknown]
> - **Confidence**: [high / medium / low]
> - **Chain ID**: [payment-fraud-surface or null]
> - **Remediation**: [e.g. "Use SELECT … FOR UPDATE on the wallet row within a database transaction before applying the debit"]
>
> ### [NOT EXPLOITABLE] Candidate title
> - **Category**: [e.g. Price Re-Fetched from DB]
> - **File**: `path/to/file.ext` (lines X–Y)
> - **Protection**: [How the control is implemented — code excerpt]
>
> ### [NEEDS MANUAL REVIEW] Candidate title
> - **Category**: [e.g. External Payment SDK Call]
> - **File**: `path/to/file.ext` (lines X–Y)
> - **Uncertainty**: [Why analysis could not resolve exploitability]
> - **Suggestion**: [What to inspect manually — e.g. "Verify that the Stripe PaymentIntent amount is set server-side, not passed from the client; trace the `amount` field through the SDK call"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/paymentlogic-batch-*.md` file and merge them into a single `sast/paymentlogic-results.md` (human-readable) and `sast/paymentlogic-results.json` (canonical schema). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/paymentlogic-batch-1.md`, `sast/paymentlogic-batch-2.md`, ... files.
2. Collect all findings from each batch file. Combine into one list, preserving classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human report to `sast/paymentlogic-results.md`:

```markdown
# Payment Logic Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Exploitable: [N]
- Likely Exploitable: [N]
- Not Exploitable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 EXPLOITABLE first, then LIKELY EXPLOITABLE, then NEEDS MANUAL REVIEW, then NOT EXPLOITABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable output to `sast/paymentlogic-results.json`. Each finding in the JSON must use the canonical schema exactly:

```json
{
  "findings": [
    {
      "id": "paymentlogic-1",
      "skill": "sast-paymentlogic",
      "severity": "high",
      "title": "Client-Supplied Unit Price Trusted in Checkout Total",
      "description": "The POST /api/checkout handler reads unit_price directly from request.json and multiplies it by quantity to compute the order total. No server-side lookup of the authoritative product price is performed. An attacker can set unit_price to 0.01 to purchase any item for a penny.",
      "location": { "file": "app/handlers/checkout.py", "line": 42, "column": 14 },
      "remediation": "Fetch the product record from the database using item_id and use product.price for the computation. Never trust a price value supplied by the client.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "payment-fraud-surface"
    }
  ]
}
```

If no exploitable or likely exploitable findings were found, still write the file with `"findings": []` so the aggregator can verify the scan ran.

6. After writing both output files, **delete all intermediate files**: `sast/paymentlogic-recon.md` and all `sast/paymentlogic-batch-*.md` files.

---

## Chain IDs

Findings from this skill may share a `chain_id` with findings from other skills when they compose into a larger attack surface.

| chain_id | Description | Contributing skills |
|---|---|---|
| `payment-fraud-surface` | Monetary manipulation chain: unauthenticated or low-privilege access + price/coupon/refund abuse → financial loss | `sast-paymentlogic`, `sast-missingauth`, `sast-race` |

**When to assign `payment-fraud-surface`**:
- Assign to any finding where the attacker can realize direct financial gain (free goods, unbounded credit, duplicate refund)
- Also assign when a race condition finding in this skill overlaps with a balance or inventory race found by `sast-race`; the `chain_id` links them so the report aggregator can surface the composed attack

**When to leave `chain_id` null**:
- Findings where the monetary manipulation path requires a high-privilege role that is already tightly controlled
- Findings classified as Needs Manual Review where exploitability is unknown

---

## Canonical Finding Schema Reference

Every finding in `sast/paymentlogic-results.json` must conform exactly to this schema (schema v2):

```json
{
  "id": "<skill>-<sequential-integer>",
  "skill": "sast-paymentlogic",
  "severity": "critical|high|medium|low|info",
  "title": "short one-line description (imperative, ≤80 chars)",
  "description": "full explanation including the taint path, what is missing, and what an attacker achieves",
  "location": {
    "file": "relative/path/from/repo/root.ext",
    "line": 123,
    "column": 10
  },
  "remediation": "specific, actionable fix — not generic advice",
  "exploitability": "reachable|conditional|unreachable|unknown",
  "confidence": "high|medium|low",
  "chain_id": "payment-fraud-surface|null"
}
```

Field notes:
- `id`: prefix is always `paymentlogic`, e.g. `paymentlogic-1`, `paymentlogic-2`
- `exploitability: reachable` → the sink is directly callable with crafted input by an authenticated or unauthenticated user
- `exploitability: conditional` → exploitable only under specific conditions (specific role, specific account state, time window)
- `confidence: high` → direct request-field→charge flow with no intervening lookup visible
- `confidence: medium` → field flows through an internal service or ORM method that might re-validate
- `confidence: low` → taint path spans multiple services or is partially obscured by abstraction

---

## Test Fixture Reference

The following annotated examples illustrate the difference between a true positive and a false negative for this skill. Use these during verify to calibrate confidence.

### True Positive — Client-Supplied Price

```python
# app/handlers/checkout.py

@app.post("/api/checkout")
def checkout():
    data = request.json  # attacker controls all fields
    item_id = data["item_id"]
    unit_price = data["unit_price"]   # price from client, never verified
    quantity = data["quantity"]
    total = unit_price * quantity     # monetary computation on untrusted input
    charge = stripe.charge(amount=int(total * 100), currency="usd")
    Order.create(item_id=item_id, total=total, charge_id=charge.id)
    return {"order_total": total}
# Finding: paymentlogic-1, severity: high, exploitability: reachable, confidence: high
# chain_id: payment-fraud-surface
```

### False Negative — Price Re-Fetched from DB (not flagged)

```python
@app.post("/api/checkout")
def checkout():
    data = request.json
    item_id = data["item_id"]         # only item_id trusted from client
    quantity = data["quantity"]
    product = Product.objects.get(pk=item_id)  # authoritative price lookup
    total = product.price * quantity           # server-side price used
    charge = stripe.charge(amount=int(total * 100), currency="usd")
    Order.create(item_id=item_id, total=total, charge_id=charge.id)
    return {"order_total": total}
# Not flagged: price is re-derived from the products table
```

### True Positive — Missing Positive-Amount Guard

```python
@app.post("/api/wallet/transfer")
def transfer():
    amount = float(request.json["amount"])   # can be negative
    # No guard: if amount <= 0: raise ...
    sender = Wallet.query.get(current_user.wallet_id)
    recipient = Wallet.query.get(request.json["to_wallet_id"])
    sender.balance -= amount    # negative amount increases sender balance
    recipient.balance += amount # negative amount decreases recipient balance
    db.session.commit()
# Finding: paymentlogic-2, severity: high, exploitability: reachable, confidence: high
# chain_id: payment-fraud-surface
```

### False Negative — Positive-Amount Guard Present (not flagged)

```python
@app.post("/api/wallet/transfer")
def transfer():
    amount = float(request.json["amount"])
    if amount <= 0:
        raise ValidationError("amount must be positive")
    sender = Wallet.query.get(current_user.wallet_id)
    ...
# Not flagged: positive-amount guard in place before monetary operation
```

### True Positive — Balance Race Without Locking

```python
@app.post("/api/wallet/withdraw")
def withdraw():
    wallet = Wallet.query.get(current_user.wallet_id)  # no FOR UPDATE
    amount = float(request.json["amount"])
    if wallet.balance < amount:                         # TOCTOU: check
        return {"error": "insufficient funds"}, 400
    wallet.balance -= amount                            # TOCTOU: use
    db.session.commit()
# Finding: paymentlogic-3, severity: high, exploitability: conditional, confidence: high
# chain_id: payment-fraud-surface
```

### False Negative — Balance Race with FOR UPDATE (not flagged)

```python
@app.post("/api/wallet/withdraw")
def withdraw():
    wallet = Wallet.query.with_for_update().get(current_user.wallet_id)  # locked
    amount = float(request.json["amount"])
    if wallet.balance < amount:
        return {"error": "insufficient funds"}, 400
    wallet.balance -= amount
    db.session.commit()
# Not flagged: SELECT … FOR UPDATE prevents the concurrent read-modify-write race
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run **after** Phase 1 completes — it depends on the recon output.
- Phase 3 must run **after** all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1–3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text, not the entire recon file. This keeps each subagent's context small and focused.
- **Server-side re-derivation is the only valid control.** Client-side form validation, JavaScript `min` attributes, API documentation that says "must be positive", and HTTP header checks that can be forged are not security controls.
- **Race conditions on monetary balances are high severity even when timing appears tight** — tools like Turbo Intruder and concurrent curl make millisecond windows trivially exploitable.
- **ORM convenience methods may obscure locking**: `Model.query.get(id)` does not add `FOR UPDATE`; `Model.query.with_for_update().get(id)` does. Read ORM docs and SQL logs to confirm.
- **Floating-point is not safe for monetary arithmetic**: look for `Decimal` usage (Python), `BigDecimal` (Java/Kotlin), or integer minor-unit arithmetic. Pure `float`/`double` monetary fields are a code quality concern and a potential manipulation surface.
- **`chain_id: "payment-fraud-surface"`** should be set on all findings where an attacker can realize direct financial gain. This allows the `sast-report` skill to surface the composed attack across `sast-paymentlogic`, `sast-race`, and `sast-missingauth`.
- When in doubt, classify as **Needs Manual Review** rather than Not Exploitable. A missed payment fraud finding costs the organization real money.
- Clean up intermediate files: delete `sast/paymentlogic-recon.md` and all `sast/paymentlogic-batch-*.md` files after the final `sast/paymentlogic-results.md` and `sast/paymentlogic-results.json` are written.
- Always emit `sast/paymentlogic-results.json` even when the findings array is empty, so the `sast-skills export` aggregator can confirm the scan ran.
