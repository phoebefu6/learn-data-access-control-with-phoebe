# Official course map - learn-data-access-control-with-phoebe

Built 2026-09-06. Hub bucket `dsec` (Data Ops & Security), difficulty tier 2. Two tracks:
leader 6 x 45 min, builder 8 x 45 min.

Running artifact: a **policy set** over one table, `saltbox.analytics.customers` at **Saltbox**,
a fictional consumer lending startup. Ten columns, three regions, five jobs. Session b8 scores
the finished set against 150 concrete access requests.

---

## The seam against sibling courses (enforced, not aspirational)

| Sibling | What it owns | What this course does instead |
|---|---|---|
| `learn-data-governance-with-phoebe` (gov, d2) | The programme: the DPO role, the law, inventory and classification as policy, consent and purpose, breach response, rights, the operating model | The enforcement machinery in the warehouse. No legal content. Classification appears only as the input that decides which column gets masked |
| `learn-gdpr-with-phoebe`, `learn-pdpa-dnc-with-phoebe` (gov) | What the law requires and how to comply | Nothing about legal obligation. This is what you build once a decision has already been made |
| `learn-dataops-with-phoebe` (dsec, d4) | The delivery practice end to end. b7 covers "Observability, secrets and IaC" in one session | Secrets get a whole session here (b6), and grants, rows, columns, tokenisation and review get one each |
| `learn-data-observability-with-phoebe` (dsec, d1) | The five signals, thresholds and detection scoring | No monitoring content. The only overlap is the shared habit of counting more than one number |
| `learn-ai-red-team-with-phoebe` (ai, d3) | Attacking model behaviour, prompt injection, jailbreaks | Nothing about models. Warehouse access only |

Access control also touches `learn-data-warehouse-with-phoebe`, which teaches warehouse
architecture and says nothing about grants; no seam work needed there.

---

## Verified facts (with their source tier)

**Tier 1, read from the primary source.**

- **Snowflake access control model**: it combines DAC (object owners grant access), RBAC
  (privileges to roles, roles to users) and UBAC. Securable objects nest organization ->
  account -> database -> schema -> objects. **Ownership** is the OWNERSHIP privilege, and in a
  regular schema the owner can grant privileges on what it owns; in a **managed access schema**
  only the schema owner or a role with MANAGE GRANTS can grant. **System roles**:
  GLOBALORGADMIN, ACCOUNTADMIN (the top-level role, combining SYSADMIN and SECURITYADMIN),
  SECURITYADMIN (manages all grants globally, plus users and roles), USERADMIN (user and role
  management only), SYSADMIN (creates warehouses, databases and objects), PUBLIC (automatically
  granted to every user). **Privilege inheritance runs upward**: privileges of a role are
  inherited by any role above it in the hierarchy. **Primary versus secondary roles**: privileges
  aggregate across active roles for ordinary statements, but CREATE statements are authorised by
  the primary role only. <https://docs.snowflake.com/en/user-guide/security-access-control-overview>
- **Snowflake row access policies**: schema-level objects created with CREATE ROW ACCESS POLICY,
  taking `(column data_type) RETURNS BOOLEAN -> condition`. A policy condition may reference a
  **mapping table**, which should live in the same database as the protected table (required if
  the policy calls IS_DATABASE_ROLE_IN_SESSION). `CURRENT_ROLE()` returns the single active role;
  `IS_ROLE_IN_SESSION()` evaluates whether a role is in the active primary or secondary roles and
  therefore handles role hierarchies better. **Limitations**: cannot prevent row insertion or
  deletion, conflict with materialized views, external tables cannot serve as mapping tables,
  subqueries in the policy body may error, and aggregate performance can degrade.
  **Evaluation order**: where an object has both a row access policy and masking policies, the
  **row access policy is evaluated first**, and a column cannot carry both policy types at once.
  <https://docs.snowflake.com/en/user-guide/security-row-intro>
- **NIST SP 800-162**, the ABAC guide: authorization is determined by evaluating attributes of
  the subject, the object, the requested operations and, in some cases, environment conditions
  against policy. The distinction from RBAC is that RBAC works on the single attribute of role
  and tends to be assigned from static organizational position, while ABAC expresses a Boolean
  rule set over many attributes and a decision can change between requests as attribute values
  change. <https://csrc.nist.gov/pubs/sp/800/162/upd2/final>

**Tier 2, secondary sources.**

- Cross-platform equivalents (BigQuery policy tags and column-level security, Databricks Unity
  Catalog row filters and column masks) are named as equivalents by category. Where a specific
  syntax is not read from the primary source, the page says so rather than inventing it.

**Nothing on the b8 bench is modelled.** Unlike a behaviour simulator, there is no human
response to estimate: the ground truth is a written access design and every counter is a count
of policy outcomes against it.

---

## Frozen canon - the b8 policy bench

Computed in node from `assets/ac-live.js` before any page quoted a number. Any page citing these
must match exactly.

| Policies on | Leaks | Over-blocks | Standing privileges |
|---|---|---|---|
| One shared analyst role | 109 | 0 | 30 |
| + mask national_id for everybody | 94 | 0 | 25 |
| + mask email and phone, except support | 70 | 0 | 17 |
| + split the shared role five ways | 22 | 0 | 1 |
| + row access policy on region | 3 | 0 | 1 |
| + pseudonymise the modelling view | **0** | **0** | **0** |
| The whole design + strip every PII column | 0 | **8** | 0 |
| The whole design + grant ACCOUNTADMIN | **109** | 0 | **30** |

- Request mix: **150 total**, of which **41 need a value in clear**, **3 need it masked** and
  **106 have no business being answered**.
- The step from 70 to 22 leaks is the **role split**, which also takes standing privileges from
  17 to 1. Role modelling does most of the work and gets the least attention.
- The 3 leaks remaining before pseudonymisation are all one cell: the data scientist holding a
  real `customer_id` where the design asked for a pseudonym.
- All **8 over-blocks** are the support agent, across `name`, `email`, `phone` and
  `support_notes`, in each of the two regions they cover.
- The ACCOUNTADMIN row is **identical to the opening state**, with every policy still defined and
  deployed.
- A **standing privilege** is a column a role can read in clear that the design does not mark
  clear for that role.

### The table, the jobs and the design

Columns: `customer_id` (identifier), `name` (direct PII), `email`, `phone` (contact PII), `dob`
(sensitive PII), `national_id` (highly sensitive), `region`, `plan` (non-sensitive), `mrr`
(financial), `support_notes` (free text, may hold PII). Regions: EU, UK, APAC.

| Job | Regions | Needs in clear | Needs masked |
|---|---|---|---|
| EU analyst | EU | customer_id, region, plan, mrr | - |
| Support agent | EU, UK | customer_id, name, email, phone, region, plan, support_notes | - |
| Data scientist | EU, UK, APAC | region, plan, mrr | customer_id |
| Finance analyst | EU, UK, APAC | customer_id, region, plan, mrr | - |
| APAC contractor | APAC | region, plan | - |

`national_id` is needed by nobody, in any form. That absence of an exception role is the teaching
point in a4 and b4.

---

## Coverage per session

`✓` = taught to working depth. `◐` = named and handed to the session or course that owns it.

### Leader track

| Session | Covers | Depth |
|---|---|---|
| a1 Who can see what, and who decided | The three counters, why an over-block is not a safe failure, where denied data actually goes | ✓ |
| a2 Roles, attributes, and why role sprawl happens | RBAC vs ABAC per NIST SP 800-162, the attribute model, the organisational causes of sprawl | ✓ |
| a3 Least privilege people can work with | Break-glass with expiry, time-bound elevation, the friction budget, the request queue as a signal | ✓ |
| a4 Classify, then mask | Three or four classes, exception roles and their justification, the free-text rule | ✓ |
| a5 Proof, not promises | What an auditor asks for, why a screenshot is not evidence, recertification | ✓ |
| a6 The access operating model | Approval and review split, the 90-day plan, the three numbers to report monthly | ✓ |
| Identity provider, SSO, MFA | Named as upstream of everything here; not taught | ◐ |

### Builder track

| Session | Covers | Depth |
|---|---|---|
| b1 Grants from first principles | Securable objects, ownership, managed access schemas, the six system roles, upward inheritance, primary vs secondary roles, the written access design | ✓ |
| b2 A role hierarchy that survives a reorg | Functional vs access roles, the two-layer pattern, what granting a role to a role really does | ✓ |
| b3 Row-level security | Row access policies, mapping tables, CURRENT_ROLE vs IS_ROLE_IN_SESSION, the documented limitations | ✓ |
| b4 Column security and dynamic masking | Masking policies with exception roles, policy tags, row-policy-first evaluation order, one policy type per column | ✓ |
| b5 Tokenisation and pseudonymisation | Surrogate keys, format-preserving tokens, quasi-identifiers and re-identification risk | ✓ |
| b6 Secrets, keys and service accounts | Rotation, short-lived credentials, service-account hygiene, the four places a password ends up in a repo | ✓ |
| b7 Access review as a pipeline | Query history against grants, unused-privilege and over-grant reports, evidence generation | ✓ |
| b8 The policy bench | The full ladder scored live, three counters, both over-corrections | ✓ |

## Not covered, by design

- **Data protection law and consent.** What the law requires is a separate discipline.
- **Authentication.** Identity providers, SSO and MFA are upstream of every control here.
- **Network and infrastructure security.** Private links, IP allowlists and encryption at rest.
- **Classification-weighted scoring on the bench.** Every request counts the same, which a real
  scoreboard would not do. Named on b8 as the first extension to make.
- **Vendor product comparison** for access-governance platforms. Categories and questions only.

## Re-verify before delivery

Row access policy limitations and the masking-policy interaction are the fastest-moving part of
this material across warehouse vendors. Re-read the row-policy page before teaching b3 and b4,
and check whether the object-type limitations still hold.
