# Learn Data Access Control with Phoebe

Fourteen sessions on who can see what in a warehouse, and on proving it. Access goes wrong in three directions at once and most teams count one of them: somebody holds a column they have no business seeing, somebody else cannot do the job they were hired for so the data reaches them through a shared spreadsheet with no logging at all, and a third pile of grants sits there needed by nobody.

**Live:** https://phoebefu6.github.io/learn-data-access-control-with-phoebe/

Two tracks. **Leader, 6 sessions, no SQL:** the three counters, RBAC against ABAC, a friction budget people can work with, classification and exception roles, evidence an auditor accepts, and the operating model. **Builder, 8 sessions:** one table locked down control by control, ending in a policy set you have actually scored.

- `assets/ac-live.js` holds the **policy bench**. Five personas, ten columns and three regions make **150 concrete access requests** against `saltbox.customers`, and every policy you switch on is really applied to all of them. Row policies evaluate before masking policies, exactly as a warehouse does it. Nothing here is modelled: the ground truth is a written access design and each counter is a count of what the policy set returned.
- **The measured ladder:** one shared analyst role gives **109 leaks, 0 over-blocks, 30 standing privileges**. Mask national_id 94. Mask email and phone with a support exception 70. **Split the shared role five ways: 22 leaks and standing privileges from 17 to 1** - the single biggest move, and it reads as administration rather than security. Row policy on region 3. Pseudonymise the modelling view **0, 0, 0**.
- **Two over-corrections, both real:** stripping every PII column holds leaks at zero and produces **8 over-blocks**, all of them the support agent, which is how phone numbers end up in a shared spreadsheet. Granting ACCOUNTADMIN clears every over-block and restores **all 109 leaks and all 30 standing privileges**, with every policy still defined and deployed, because a role above the policy layer is not constrained by it.
- **The seam against siblings is enforced.** What the law requires belongs to the governance, GDPR and PDPA courses; this is the machinery that implements a decision once it has been made. Authentication, SSO and MFA are upstream and out of scope.
- Running artifact: a **policy set** over `saltbox.customers` at Saltbox, a fictional consumer lending startup.
- Full source map, verification tiers and frozen canon: `materials/official-course-map.md`

by Phoebe Fu
