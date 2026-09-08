/* ac-live.js - the policy bench for learn-data-access-control-with-phoebe.

   Real evaluation, not a quiz: five personas, ten columns and three regions make 150
   concrete access requests against saltbox.customers. Every policy you switch on is a
   real rule that this engine applies to every request, and the three counters are
   counted from what the policy set actually returned.

   Nothing here is modelled. The ground truth is a written access design (who legitimately
   needs which column, in clear or masked form, for which regions) and the engine compares
   the policy set's output against it request by request.

   Exposes window.AC_ENGINE and renders into [data-ac-bench]. */
(function (root) {
  "use strict";

  /* ============================================================
     1. the table, the personas and the written access design
     ============================================================ */

  var COLUMNS = [
    { id: "customer_id",   label: "customer_id",   klass: "identifier" },
    { id: "name",          label: "name",          klass: "direct PII" },
    { id: "email",         label: "email",         klass: "contact PII" },
    { id: "phone",         label: "phone",         klass: "contact PII" },
    { id: "dob",           label: "dob",           klass: "sensitive PII" },
    { id: "national_id",   label: "national_id",   klass: "highly sensitive" },
    { id: "region",        label: "region",        klass: "non-sensitive" },
    { id: "plan",          label: "plan",          klass: "non-sensitive" },
    { id: "mrr",           label: "mrr",           klass: "financial" },
    { id: "support_notes", label: "support_notes", klass: "free text, may hold PII" }
  ];

  var REGIONS = ["EU", "UK", "APAC"];

  /* need: "clear" = must see the real value to do the job
           "masked" = must have the column, must not have the real value
           "none"  = has no business seeing it at all
     A request for a region outside the persona's remit is "none" whatever the column. */
  var PERSONAS = [
    { id: "analyst_eu", label: "EU analyst", regions: ["EU"],
      job: "Revenue and plan-mix reporting for the EU book.",
      need: { customer_id: "clear", region: "clear", plan: "clear", mrr: "clear" } },

    { id: "support_agent", label: "Support agent", regions: ["EU", "UK"],
      job: "Answers tickets. Has to reach the actual human on the phone.",
      need: { customer_id: "clear", name: "clear", email: "clear", phone: "clear",
              region: "clear", plan: "clear", support_notes: "clear" } },

    { id: "data_scientist", label: "Data scientist", regions: ["EU", "UK", "APAC"],
      job: "Churn model over the whole book. Needs the row, never the person.",
      need: { customer_id: "masked", region: "clear", plan: "clear", mrr: "clear" } },

    { id: "finance", label: "Finance analyst", regions: ["EU", "UK", "APAC"],
      job: "Group revenue. Never contacts a customer.",
      need: { customer_id: "clear", region: "clear", plan: "clear", mrr: "clear" } },

    { id: "contractor_apac", label: "APAC contractor", regions: ["APAC"],
      job: "External. Plan-mix counts for the APAC launch, nothing else.",
      need: { region: "clear", plan: "clear" } }
  ];

  function requirement(persona, column, region) {
    if (persona.regions.indexOf(region) < 0) return "none";
    return persona.need[column] || "none";
  }

  var REQUESTS = [];
  PERSONAS.forEach(function (p) {
    COLUMNS.forEach(function (c) {
      REGIONS.forEach(function (r) {
        REQUESTS.push({ persona: p, column: c, region: r, need: requirement(p, c.id, r) });
      });
    });
  });

  /* ============================================================
     2. the policies - each is a real rule applied to every request
     ============================================================ */

  var POLICIES = [
    { id: "mask_natid", family: "Masking", label: "Mask national_id for everybody",
      blurb: "A column-level masking policy with no exception list. Nobody in the warehouse has a job that needs it in clear." },
    { id: "mask_contact", family: "Masking", label: "Mask email and phone, except support",
      blurb: "The same policy with one exception role. The exception is the whole design decision." },
    { id: "role_split", family: "Roles", label: "Split the shared role into five",
      blurb: "One role per job with column grants that match the written access design, instead of one analyst role holding everything." },
    { id: "row_policy", family: "Rows", label: "Row access policy on region",
      blurb: "A mapping table of role to region, applied as a row filter. Evaluated before any masking policy." },
    { id: "pseudonymise_ds", family: "Masking", label: "Pseudonymise the modelling view",
      blurb: "A surrogate key replaces customer_id for the data science role, so rows stay joinable and people stay unidentifiable." },
    { id: "strip_all_pii", family: "Over-correction", label: "Strip every PII column from everyone",
      blurb: "The reflex after an audit finding. Watch the second counter, not the first." },
    { id: "grant_accountadmin", family: "Over-correction", label: "Grant ACCOUNTADMIN to unblock people",
      blurb: "The Friday-afternoon fix. It really does clear every over-block." }
  ];

  /* Evaluate one request under a policy set. Returns "clear" | "masked" | "denied". */
  function evaluate(req, on) {
    var pid = req.persona.id, col = req.column.id;

    /* The top-level role overrides everything below it, which is exactly why it is
       the wrong tool for unblocking somebody. */
    if (on.grant_accountadmin) return "clear";

    /* Row access policies are evaluated before masking policies. */
    if (on.row_policy && req.persona.regions.indexOf(req.region) < 0) return "denied";

    var PII = ["name", "email", "phone", "dob", "national_id", "support_notes"];
    if (on.strip_all_pii && PII.indexOf(col) >= 0) return "denied";

    /* Column grants: split roles grant only what the access design asked for. */
    if (on.role_split) {
      var need = req.persona.need[col];
      if (!need) return "denied";
    }

    /* Masking policies apply on top of whatever the grants allowed. */
    if (on.pseudonymise_ds && pid === "data_scientist" &&
        ["customer_id", "name", "email", "phone", "dob", "national_id", "support_notes"].indexOf(col) >= 0) {
      return "masked";
    }
    if (on.mask_natid && col === "national_id") return "masked";
    if (on.mask_contact && (col === "email" || col === "phone") && pid !== "support_agent") return "masked";

    return "clear";
  }

  /* A grant is "standing" if the role holds a column in clear that no request of that
     persona legitimately needs in clear. This is the unused-privilege audit finding. */
  function standingPrivileges(on) {
    var n = 0;
    PERSONAS.forEach(function (p) {
      COLUMNS.forEach(function (c) {
        var got = evaluate({ persona: p, column: c, region: p.regions[0], need: null }, on);
        if (got === "clear" && p.need[c.id] !== "clear") n++;
      });
    });
    return n;
  }

  function run(on) {
    var leaks = [], overBlocks = [], ok = 0;
    REQUESTS.forEach(function (req) {
      var got = evaluate(req, on);
      var need = req.need;
      if (need === "clear") {
        if (got === "clear") ok++;
        else overBlocks.push({ req: req, got: got });
      } else if (need === "masked") {
        if (got === "masked" || got === "denied") ok++;
        else leaks.push({ req: req, got: got });
      } else {
        if (got === "clear") leaks.push({ req: req, got: got });
        else ok++;
      }
    });
    return {
      total: REQUESTS.length, ok: ok,
      leaks: leaks.length, overBlocks: overBlocks.length,
      standing: standingPrivileges(on),
      leakList: leaks, overList: overBlocks
    };
  }

  var RUNGS = [
    { label: "One shared analyst role", on: [] },
    { label: "+ mask national_id", on: ["mask_natid"] },
    { label: "+ mask email and phone", on: ["mask_natid", "mask_contact"] },
    { label: "+ split the role five ways", on: ["mask_natid", "mask_contact", "role_split"] },
    { label: "+ row policy on region", on: ["mask_natid", "mask_contact", "role_split", "row_policy"] },
    { label: "+ pseudonymise the modelling view", on: ["mask_natid", "mask_contact", "role_split", "row_policy", "pseudonymise_ds"] }
  ];

  function ladder() {
    return RUNGS.map(function (r) {
      var on = {};
      r.on.forEach(function (id) { on[id] = true; });
      var res = run(on);
      return { label: r.label, leaks: res.leaks, overBlocks: res.overBlocks, standing: res.standing };
    });
  }

  root.AC_ENGINE = {
    COLUMNS: COLUMNS, REGIONS: REGIONS, PERSONAS: PERSONAS, POLICIES: POLICIES,
    REQUESTS: REQUESTS, run: run, ladder: ladder, RUNGS: RUNGS, evaluate: evaluate
  };
})(typeof window !== "undefined" ? window : globalThis);

/* ============================================================
   3. the widget - renders the policy bench into [data-ac-bench]
   ============================================================ */
(function () {
  "use strict";
  if (typeof document === "undefined") return;
  var E = window.AC_ENGINE;
  if (!E) return;

  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt !== undefined && txt !== null) n.textContent = txt;
    return n;
  }

  var PRESETS = [
    { label: "One shared role", on: [] },
    { label: "Masking only", on: ["mask_natid", "mask_contact"] },
    { label: "Roles and rows", on: ["mask_natid", "mask_contact", "role_split", "row_policy"] },
    { label: "The whole design", on: ["mask_natid", "mask_contact", "role_split", "row_policy", "pseudonymise_ds"] }
  ];

  document.querySelectorAll("[data-ac-bench]").forEach(function (host) {
    var state = {};

    var wrap = el("div", "wk pb-wrap");
    var head = el("div", "wk-head");
    head.appendChild(el("b", null, "The policy bench"));
    head.appendChild(el("span", null, "saltbox.customers · 5 personas · 10 columns · 3 regions · 150 requests"));
    wrap.appendChild(head);

    var body = el("div", "wk-body");
    body.appendChild(el("p", "hb-honesty",
      "Nothing here is modelled. The written access design says who needs which column in " +
      "clear, which masked, and for which regions. Every policy you switch on is applied to " +
      "all 150 requests and the three counters are counted from what came back."));

    var reads = el("div", "pb-reads");
    function readout(cls, label) {
      var box = el("div", "pb-read " + cls);
      var big = el("b", "pb-big", "-");
      box.appendChild(big);
      box.appendChild(el("span", "pb-rlab", label));
      reads.appendChild(box);
      return big;
    }
    var outLeak = readout("pb-r1", "leaks");
    var outOver = readout("pb-r2", "over-blocks");
    var outStand = readout("pb-r3", "standing privileges");
    body.appendChild(reads);

    var presetRow = el("div", "pb-presets");
    presetRow.appendChild(el("span", "pb-plab", "Presets"));
    PRESETS.forEach(function (p) {
      var b = el("button", "hb-btn", p.label);
      b.type = "button";
      b.addEventListener("click", function () {
        state = {};
        p.on.forEach(function (id) { state[id] = true; });
        sync(); paint();
      });
      presetRow.appendChild(b);
    });
    body.appendChild(presetRow);

    var boxes = {};
    var list = el("div", "pb-policies");
    E.POLICIES.forEach(function (pol) {
      var row = el("label", "pb-pol" + (pol.family === "Over-correction" ? " pb-anti" : ""));
      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.addEventListener("change", function () { state[pol.id] = cb.checked; paint(); });
      boxes[pol.id] = cb;
      var txt = el("span", "pb-ptxt");
      txt.appendChild(el("b", null, pol.label));
      txt.appendChild(el("span", "pb-pblurb", pol.blurb));
      row.appendChild(cb);
      row.appendChild(el("span", "pb-fam", pol.family));
      row.appendChild(txt);
      list.appendChild(row);
    });
    body.appendChild(list);

    body.appendChild(el("p", "pb-gridlab",
      "Every persona against every column, in their own regions. Hover a cell to read the verdict."));
    var grid = el("div", "pb-gridwrap");
    body.appendChild(grid);

    var legend = el("div", "pb-legend");
    [["pb-c-ok", "as designed"], ["pb-c-leak", "leak"], ["pb-c-over", "over-block"]].forEach(function (p) {
      var s = el("span", "pb-lg");
      s.appendChild(el("i", p[0]));
      s.appendChild(el("span", null, p[1]));
      legend.appendChild(s);
    });
    body.appendChild(legend);

    var notes = el("div", "pb-notes");
    body.appendChild(notes);
    wrap.appendChild(body);

    var foot = el("div", "wk-foot");
    foot.appendChild(el("span", null,
      "A standing privilege is a column a role holds in clear that no request of that role " +
      "needed in clear. It is the finding an access review reports."));
    wrap.appendChild(foot);
    host.appendChild(wrap);

    function sync() {
      Object.keys(boxes).forEach(function (id) { boxes[id].checked = !!state[id]; });
    }

    function paint() {
      var res = E.run(state);
      outLeak.textContent = res.leaks;
      outOver.textContent = res.overBlocks;
      outStand.textContent = res.standing;

      grid.textContent = "";
      var table = el("table", "pb-grid");
      var thead = el("thead");
      var hr = el("tr");
      hr.appendChild(el("th", null, "Persona"));
      E.COLUMNS.forEach(function (c) {
        var th = el("th", "pb-colh", c.id);
        th.title = c.id + " - " + c.klass;
        hr.appendChild(th);
      });
      thead.appendChild(hr);
      table.appendChild(thead);

      var tbody = el("tbody");
      E.PERSONAS.forEach(function (p) {
        var tr = el("tr");
        var th = el("th", "pb-rowh");
        th.appendChild(el("b", null, p.label));
        th.appendChild(el("span", "pb-regions", p.regions.join(" · ")));
        th.title = p.job;
        tr.appendChild(th);

        E.COLUMNS.forEach(function (c) {
          /* score this persona and column across their own regions plus one they must not
             reach, so a row leak shows up in the grid rather than only in the counter */
          var verdict = "ok", detail = [];
          E.REGIONS.forEach(function (r) {
            var req = { persona: p, column: c, region: r, need: (p.regions.indexOf(r) < 0 ? "none" : (p.need[c.id] || "none")) };
            var got = E.evaluate(req, state);
            if (req.need === "clear" && got !== "clear") { verdict = "over"; detail.push(r + ": needs clear, got " + got); }
            else if (req.need === "masked" && got === "clear") { if (verdict !== "over") verdict = "leak"; detail.push(r + ": needs masked, got clear"); }
            else if (req.need === "none" && got === "clear") { if (verdict !== "over") verdict = "leak"; detail.push(r + ": no business seeing it, got clear"); }
          });
          var td = el("td", "pb-cell pb-c-" + (verdict === "ok" ? "ok" : verdict === "leak" ? "leak" : "over"));
          td.textContent = verdict === "ok" ? "·" : verdict === "leak" ? "!" : "x";
          td.title = p.label + " / " + c.id + "\n" + (detail.length ? detail.join("\n") : "as designed in every region");
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      grid.appendChild(table);

      notes.textContent = "";
      if (res.leaks === 0 && res.overBlocks === 0 && res.standing === 0) {
        notes.appendChild(el("p", "dh-verdict",
          "Zero leaks, zero over-blocks, zero standing privileges across 150 requests. " +
          "Everybody can do their job and nobody holds a column they cannot justify."));
      }
      if (res.overBlocks > 0) {
        var who = {};
        res.overList.forEach(function (o) { who[o.req.persona.label] = (who[o.req.persona.label] || 0) + 1; });
        var lines = Object.keys(who).map(function (k) { return k + " (" + who[k] + ")"; }).join(", ");
        notes.appendChild(el("p", "dh-verdict warn",
          res.overBlocks + " over-blocks. Somebody cannot do their job: " + lines +
          ". An over-block is not a safe failure, it is a ticket that gets solved with a shared login."));
      }
      if (res.standing >= 20) {
        notes.appendChild(el("p", "dh-verdict warn",
          res.standing + " standing privileges. This is what an access review reports, and it " +
          "is the number that survives long after the person who needed it has left."));
      }
    }

    sync();
    paint();
  });
})();
