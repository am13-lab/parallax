package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"parallax/runner"
)

// RunMeta describes one embedded run for the history selector.
type RunMeta struct {
	Stamp     string         `json:"stamp"`
	StartedAt string         `json:"started_at"`
	Seed      int64          `json:"seed,omitempty"`
	Clients   string         `json:"clients,omitempty"`
	Command   string         `json:"command,omitempty"`
	Summary   runner.Summary `json:"summary"`
}

// RunPayload is one embedded run: its metadata plus the full report and findings.
type RunPayload struct {
	Meta     RunMeta         `json:"meta"`
	Report   json.RawMessage `json:"report"`
	Findings json.RawMessage `json:"findings"`
}

// WriteHTML renders the report and its findings as one self-contained HTML
// page: no external assets, no JavaScript dependencies, openable directly
// from disk or attached to CI artifacts. The full v1 report JSON is embedded
// verbatim in a script element; the page renders it client-side.
//
// Pass findings to include triage state (allowlist suppression, severity
// downgrade). Nil computes them fresh from the report without an allowlist.
func WriteHTML(rep *runner.Report, findings []Finding, ruleTexts map[string]string) ([]byte, error) {
	run, err := runPayload(rep, findings)
	if err != nil {
		return nil, err
	}
	return WriteHTMLRuns([]RunPayload{run}, 0, ruleTexts, nil)
}

// WriteHTMLRuns embeds several runs into one page with a history selector;
// current selects which run is shown initially.
// WriteHTMLRuns embeds several runs into one page with a history selector;
// current selects which run is shown initially. ruleTexts maps a spec rule
// id to its human-readable requirement text for hover explanations.
func WriteHTMLRuns(runs []RunPayload, current int, ruleTexts, ruleLinks map[string]string) ([]byte, error) {
	if len(runs) == 0 {
		return nil, fmt.Errorf("no runs to render")
	}
	if current < 0 || current >= len(runs) {
		current = 0
	}
	payload, err := json.Marshal(struct {
		Runs      []RunPayload      `json:"runs"`
		Current   int               `json:"current"`
		Generated string            `json:"generated"`
		Rules     map[string]string `json:"rules,omitempty"`
		RuleLinks map[string]string `json:"rule_links,omitempty"`
	}{Runs: runs, Current: current, Generated: time.Now().UTC().Format(time.RFC3339), Rules: ruleTexts, RuleLinks: ruleLinks})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, struct{ Data template.JS }{Data: template.JS(payload)}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// clientMix aggregates endpoint client types, e.g. "geth×2 + erigon×1".
func clientMix(eps []runner.EndpointFingerprint) string {
	order := []string{}
	count := map[string]int{}
	for _, e := range eps {
		if e.ClientType == "" {
			continue
		}
		if count[e.ClientType] == 0 {
			order = append(order, e.ClientType)
		}
		count[e.ClientType]++
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", k, count[k]))
	}
	return strings.Join(parts, " + ")
}

// runPayload packs one report + findings into an embeddable payload. The
// meta summary is shared with LoadHistory via metaOf.
func runPayload(rep *runner.Report, findings []Finding) (RunPayload, error) {
	if findings == nil {
		findings = BuildFindings(rep, false)
	}
	repJSON, err := json.Marshal(rep)
	if err != nil {
		return RunPayload{}, fmt.Errorf("marshal report: %w", err)
	}
	findJSON, err := json.Marshal(findings)
	if err != nil {
		return RunPayload{}, fmt.Errorf("marshal findings: %w", err)
	}
	return RunPayload{
		Meta:     metaOf(rep),
		Report:   repJSON,
		Findings: findJSON,
	}, nil
}

var htmlTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Parallax Differential Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1f2630;--fg:#e6edf3;--dim:#8b949e;
--line:#30363d;--green:#3fb950;--red:#f85149;--orange:#d29922;--gray:#6e7681;--blue:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:0 24px}
.topbar{position:sticky;top:0;z-index:30;background:rgba(13,17,23,.92);backdrop-filter:blur(6px);border-bottom:1px solid var(--line)}
.topbar-in{display:flex;align-items:center;gap:18px;height:52px}
.brand{font-weight:700;font-size:15px;letter-spacing:.02em}
.tabs{display:flex;gap:14px;margin-left:auto}
.tab{padding:5px 2px;border:none;background:none;color:var(--dim);cursor:pointer;font-size:13px;border-bottom:2px solid transparent}
.tab.active{color:var(--fg);border-bottom-color:var(--blue)}
.tab:hover{color:var(--fg)}
.tab.sub{padding:5px 12px;border-radius:8px}
.tab.sub.active{background:var(--panel2);border-bottom-color:transparent}
.meta{color:var(--dim);font-size:12px;margin-top:14px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 4px}
.badge{padding:3px 10px;border-radius:12px;font-size:12px;background:var(--panel);border:1px solid var(--line)}
.badge b{font-size:13px}
.badge.pass b{color:var(--green)}.badge.div b{color:var(--red)}.badge.skip b{color:var(--gray)}.badge.err b{color:var(--orange)}
h2.sec{font-size:13px;margin:28px 0 10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--line);padding-bottom:6px}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px;align-items:center}
.bar input,.bar select{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:13px}
.bar input{flex:1;min-width:180px}
.bar input:focus{outline:none;border-color:var(--blue)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.card.click{cursor:pointer}
.card.click:hover{border-color:var(--blue)}
.card.active{border-color:var(--blue);background:var(--panel2)}
.fhead{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.fid{color:var(--dim);font-size:12px;min-width:110px}
.tid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.chip{padding:1px 8px;border-radius:10px;font-size:11px;border:1px solid var(--line);color:var(--dim);white-space:nowrap}
.chip.sev-CRITICAL{color:#ff7a7a;border-color:#ff7a7a}
.chip.sev-HIGH{color:var(--red);border-color:var(--red)}
.chip.sev-MEDIUM{color:var(--orange);border-color:var(--orange)}
.chip.sev-INFO,.chip.sev-LOW{color:var(--dim)}
.chip.st-pass{color:var(--green);border-color:var(--green)}
.chip.st-divergent{color:var(--red);border-color:var(--red)}
.chip.st-error{color:var(--orange);border-color:var(--orange)}
.chip.st-skipped{color:var(--gray);border-color:var(--gray)}
.chip.sup{color:#111;background:var(--orange);border-color:var(--orange);font-weight:600}
.cause{margin-top:6px;color:var(--fg)}
.outs{margin-top:6px;color:var(--dim);font-size:12px}
.outs b{color:#ffb0b0;font-weight:600}
.rules{margin-top:4px;color:var(--dim);font-size:11px;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.reason{margin-top:6px;padding:6px 10px;background:var(--panel2);border-left:3px solid var(--orange);border-radius:4px;color:var(--dim);font-size:12px;white-space:pre-wrap}
.detail{display:none;margin-top:10px;border-top:1px solid var(--line);padding-top:8px}
.detail.open{display:block}
.cr{display:flex;gap:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:2px 0}
.cr .n{min-width:140px;color:var(--dim)}
.cr .v{word-break:break-all}
.cr.isOut .n,.cr.isOut .v{color:#ffb0b0}
.ev{color:var(--dim);font-size:12px;margin-top:4px}
.empty{color:var(--dim);padding:30px;text-align:center}
.count{color:var(--dim);font-size:12px;margin:6px 0}
details.group{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--panel)}
details.group>summary{cursor:pointer;padding:9px 14px;font-size:13px;list-style:none;display:flex;gap:8px;align-items:center;flex-wrap:wrap;user-select:none}
details.group>summary::-webkit-details-marker{display:none}
details.group>summary .cnt{color:var(--dim);font-size:12px}
details.group>summary::after{content:"▸";margin-left:auto;color:var(--dim)}
details.group[open]>summary::after{content:"▾"}
details.group>summary:hover{color:var(--blue)}
details.group>div.body{padding:2px 14px 12px}
.divdetail{padding:6px 0 10px}
.crrow{display:flex;gap:8px;justify-content:space-between;align-items:center;flex-wrap:wrap;font-size:12px;padding:5px 10px;border:1px solid var(--line);border-radius:6px;margin-top:6px}
.crrow.isout{border-color:rgba(248,81,73,.5);background:rgba(248,81,73,.05)}
.crrow.isme{outline:1px solid var(--blue)}
.crrow.inline{justify-content:flex-start}
.crrow .n{color:var(--dim)}
.clients{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.clients.left{justify-content:flex-start}
.cchip{padding:2px 9px;border-radius:8px;font-size:12px;font-family:ui-monospace,Menlo,monospace;border:1px solid var(--line);color:var(--fg)}
.cchip.ok{border-color:rgba(63,185,80,.55);color:var(--green)}
.cchip.bad{border-color:rgba(248,81,73,.6);color:#ffb0b0;background:rgba(248,81,73,.08)}
.cchip[data-reason]{position:relative;cursor:help}
.cchip[data-reason]:hover::after,.mc[data-reason]:hover::after{content:attr(data-reason);position:absolute;left:0;top:calc(100% + 6px);z-index:60;max-width:640px;width:max-content;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--fg);font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-all;text-align:left;box-shadow:0 6px 20px rgba(0,0,0,.45)}
.mc[data-reason]{position:relative;cursor:help}
.stepsum{cursor:pointer}
.stepbody{padding:2px 0 6px 22px}
.stepwant .vc.expect.big{font-size:13px;padding:3px 12px}
.cmdblock{margin:6px 0;padding:8px 12px;background:#090d13;border:1px solid var(--line);border-radius:8px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.6;color:#cdd9e5;white-space:pre-wrap;word-break:break-all;text-align:left}
.vc{display:inline-block;text-align:center;padding:1px 8px;border-radius:8px;font-size:11px;
font-family:ui-monospace,Menlo,monospace;border:1px solid var(--line);color:var(--dim)}
.vc.expect{color:var(--blue);border-color:var(--blue)}
.vc.match{color:var(--green);border-color:var(--green)}
.vc.deviate{color:var(--red);border-color:var(--red)}
.vc.me{outline:1px solid var(--blue)}
.dot{width:8px;height:8px;border-radius:50%;flex:none;display:inline-block}
.dot.pass{background:var(--green)}.dot.out{background:var(--red)}.dot.ano{background:var(--orange)}.dot.idle{background:var(--gray)}
.ccards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;margin-bottom:10px}
.ccard{border:1px solid var(--line);border-top:3px solid var(--line);border-radius:12px;padding:12px 14px;cursor:pointer;background:var(--panel)}
.ccard:hover{border-color:var(--blue)}
.ccard.pass{border-top-color:var(--green)}
.ccard.out{border-top-color:var(--red)}
.ccard.ano{border-top-color:var(--orange)}
.ccard.idle{border-top-color:var(--gray)}
.ccard .big{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px;font-family:ui-monospace,Menlo,monospace}
.ccard .sub{color:var(--dim);font-size:12px;margin-top:6px}
.ccard .sub .p{color:var(--green)}.ccard .sub .r{color:var(--red)}.ccard .sub .a{color:var(--orange)}.ccard .sub .x{color:var(--gray)}
.minibar{height:4px;border-radius:2px;background:var(--panel2);margin-top:10px;overflow:hidden;display:flex}
.minibar div{height:100%}
.minibar .g{background:var(--green)}.minibar .r{background:var(--red)}.minibar .a{background:var(--orange)}.minibar .x{background:var(--gray)}
.lg.g{color:var(--green)}.lg.r{color:var(--red)}.lg.a{color:var(--orange)}.lg.x{color:var(--gray)}
.backbtn{background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;padding:0}
.backbtn:hover{color:var(--blue)}
.crumbs{display:flex;align-items:center;gap:10px;margin:16px 0 10px}
.crumblink{background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;padding:0}
.crumblink:hover{color:var(--blue)}
.crumbsep{color:var(--dim)}
.crumbhere{font-size:18px;font-weight:700;display:flex;align-items:center;gap:8px;color:var(--fg);font-family:ui-monospace,Menlo,monospace}
.acwrap{position:relative;flex:none;width:300px}
.acwrap input{width:100%}
.acpop{position:absolute;top:100%;left:0;right:0;z-index:10;display:none;background:var(--panel2);border:1px solid var(--line);border-radius:8px;margin-top:4px;max-height:240px;overflow:auto;box-shadow:0 6px 20px rgba(0,0,0,.4)}
.acitem{padding:6px 12px;font-family:ui-monospace,Menlo,monospace;font-size:12px;cursor:pointer}
.acitem:hover{background:var(--panel);color:var(--blue)}
table.matrix{width:100%;border-collapse:collapse;font-size:12px}
table.matrix-sum{table-layout:fixed}
table.matrix-sum thead th:first-child{width:48%}
table.matrix th{position:sticky;top:52px;background:var(--panel2);color:var(--dim);text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace;font-weight:600;z-index:5}
table.matrix td{padding:5px 10px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace;vertical-align:top}
tr.mrow{cursor:pointer}
tr.mrow:hover td{background:var(--panel2)}
tr.mrow.open td{background:var(--panel2)}
tr.mrow .caret{display:inline-block;width:12px;color:var(--dim);font-size:11px}
tr.mrow.open .caret{transform:rotate(90deg)}
tr.mdetail td{background:var(--panel);padding:6px 10px 14px}
tr.mdetail{display:none}
tr.mdetail.open{display:table-row}
.detailbox{border:1px solid var(--line);border-left:3px solid var(--blue);border-radius:8px;background:var(--bg);padding:10px 14px}
.mc{white-space:nowrap}
.mc.ok{color:var(--green)}
.mc.bad{color:var(--red);font-weight:700}
.mc.warn{color:var(--orange)}
.mc.x{color:var(--gray)}
tr.mrow td.mtest{display:grid;grid-template-columns:12px 10px minmax(0,1fr) auto;gap:2px 8px;align-items:start}
.mstat{display:contents}
.mstat .caret{grid-column:1;grid-row:1;color:var(--dim);font-size:11px}
.mstat .dot{grid-column:2;grid-row:1;margin-top:5px}
.mstat .tid{grid-column:3;grid-row:1;min-width:0;word-break:break-all}
.mstat .mrules{grid-column:3/-1;color:var(--dim);font-size:11px;margin-top:2px;display:flex;gap:8px;flex-wrap:wrap}
tr.mrow td.mtest .chip{grid-column:4;grid-row:1;margin-top:1px}
.rulechip[data-reason]{position:relative;cursor:help}
.rulechip.linkable{cursor:pointer;text-decoration:underline;text-underline-offset:3px}
.rulechip[data-reason]:hover::after{content:attr(data-reason);position:absolute;left:0;top:calc(100% + 6px);z-index:60;max-width:560px;width:max-content;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--fg);font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;text-align:left;box-shadow:0 6px 20px rgba(0,0,0,.45)}
</style>
</head>
<body>
<div class="topbar">
  <div class="wrap topbar-in">
    <span class="brand">Parallax Differential Report</span>
    <nav class="tabs">
      <button class="tab active" id="tab-summary">Summary</button>
      <button class="tab" id="tab-findings">Findings</button>
      <button class="tab sub" id="tab-history">History</button>
    </nav>
  </div>
</div>
<div class="wrap">
<div class="meta" id="meta"></div>
<div class="badges" id="badges"></div>
<div id="view-summary"></div>
<div id="view-client" style="display:none">
  <div class="crumbs" id="client-crumbs"></div>
  <div class="bar">
    <div class="acwrap">
      <input id="q-client" type="search" placeholder="filter by test id" autocomplete="off">
      <div class="acpop" id="ac-pop"></div>
    </div>
  </div>
  <div id="client-out"></div>
</div>
<div id="view-findings" style="display:none">
  <div class="bar">
    <input id="q-find" type="search" placeholder="filter by test id, description, spec rule">
    <select id="sel-sev"><option value="">any severity</option></select>
    <select id="sel-sup"><option value="">all findings</option><option value="active">active only</option><option value="sup">suppressed only</option></select>
  </div>
  <div id="findings-out"></div>
</div>
<div id="view-history" style="display:none"></div>
<div class="meta" id="footer" style="margin-top:24px">generated <span id="gen"></span> &middot; parallax schema v1</div>
</div>
<script type="application/json" id="parallax-report">{{.Data}}</script>
<script>
"use strict";
const raw = JSON.parse(document.getElementById("parallax-report").textContent);
const RULES = raw.rules || {};
const RULE_LINKS = raw.rule_links || {};
function specChip(id, label) {
  const c = el("span", "rulechip", label || (id + " ⓘ"));
  const txt = RULES[id];
  if (txt) c.setAttribute("data-reason", txt + (RULE_LINKS[id] ? "\n↗ click to open the spec source" : ""));
  if (RULE_LINKS[id]) {
    c.classList.add("linkable");
    c.addEventListener("click", () => window.open(RULE_LINKS[id], "_blank"));
  }
  return c;
}
const runs = raw.runs && raw.runs.length ? raw.runs : [{ meta: {}, report: raw.report || {}, findings: raw.findings || [] }];
let currentRun = (typeof raw.current === "number" && raw.current >= 0 && raw.current < runs.length) ? raw.current : 0;
let currentTab = "summary";
let rep = {}, findings = [], results = [], clientNames = [], knownIds = new Set(), runCmd = "";

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function chip(cls, text) { return el("span", "chip " + cls, text); }
function match(text, q) { return !q || text.toLowerCase().includes(q.toLowerCase()); }

// ---- per-run apply: rebind data + header, re-render every view ----
function applyRun(i) {
  currentRun = Math.max(0, Math.min(i, runs.length - 1));
  const run = runs[currentRun] || {};
  rep = run.report || {};
  findings = run.findings || [];
  results = rep.results || [];
  currentClient = "";
  document.getElementById("q-find").value = "";
  document.getElementById("sel-sup").value = "";
  const selSev = document.getElementById("sel-sev");
  selSev.value = "";
  while (selSev.options.length > 1) selSev.remove(1);
  const sevs = [];
  findings.forEach(f => { if (f.severity && !sevs.includes(f.severity)) sevs.push(f.severity); });
  sevs.sort().forEach(sv => selSev.append(new Option(sv, sv)));
  const s = rep.summary || {};
  document.getElementById("meta").textContent =
    "started " + (rep.started_at || "?") + " · seed " + rep.seed + " · preset " + (rep.chain_preset || "?") +
    (s.stop_reason ? " · stop: " + s.stop_reason : "");
  const badges = [
    ["total", s.total], ["pass", s.passed, "pass"], ["divergent", s.divergent, "div"],
    ["skipped", s.skipped, "skip"], ["errors", s.errors, "err"],
    ["findings", findings.length, "div"],
  ];
  const badgeBox = document.getElementById("badges");
  badgeBox.textContent = "";
  badges.forEach(b => {
    const d = el("div", "badge" + (b[2] ? " " + b[2] : ""));
    d.append(el("b", null, b[1] != null ? b[1] : 0), " " + b[0]);
    badgeBox.append(d);
  });
  document.getElementById("gen").textContent = raw.generated || "";
  runCmd = baseRunCmd(rep.command) ||
    ("go run ./cmd/parallax run -env kurtosis -enclave <enclave> -args-file configs/net.yaml -seed " + (rep.seed != null ? rep.seed : 42));
  // tests covered by a suppressed (known) finding are informational: their
  // divergence is a registered implementation difference, not a new finding.
  knownIds = new Set(findings.filter(f => f.suppressed)
    .flatMap(f => (f.evidence || []).map(e => e.test_id)));

  // ---- client discovery ----
  clientNames = [];
  (rep.endpoints || []).forEach(e => { if (e.name && !clientNames.includes(e.name)) clientNames.push(e.name); });
  results.forEach(r => (r.divergences || []).forEach(d =>
    Object.keys(d.client_results || {}).forEach(n => { if (!clientNames.includes(n)) clientNames.push(n); })));

  renderSummary();
  renderFindings();
  renderHistory();
  tab(currentTab);
}
// baseRunCmd strips any -test filters the recorded command already had, so
// a single-test rerun does not stack a second -test on reproduction.
function baseRunCmd(cmd) {
  const toks = String(cmd || "").split(/\s+/);
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    if (toks[i] === "-test" || toks[i] === "--test") { i++; continue; }
    out.push(toks[i]);
  }
  return out.join(" ");
}
function reproduceCmd(r) { return runCmd + " -test '" + r.test_id + "'"; }

function isOutlier(d, name) { return (d.outlier_clients || []).includes(name); }
function verdictOf(d, name) {
  const v = (d.client_results || {})[name];
  if (v === undefined) return null;
  if (v === "accept") return "accept";
  if (String(v).indexOf("reject") === 0) return "reject";
  return "other";
}
function specLine(rules, kids) {
  const all = (rules || []).concat(kids || []);
  if (!all.length) return null;
  const w = el("div", "rules");
  all.forEach(id => w.append(specChip(id, id + " ⓘ")));
  return w;
}
function shortName(n) { return String(n).replace(/^cl-\d+-/, ""); }

// prettyTestId renders a generated case id readably: strips the long common
// prefix, word-splits, hides the trailing hash (kept in the tooltip).
function prettyTestId(id) {
  let s = String(id);
  s = s.replace(/^ir_(stateless|seq)\.cryptomsg\.generated(_sequence)?\./, "");
  s = s.replace(/^ir_stateless\.cryptomsg\./, "");
  s = s.replace(/\.[0-9a-f]{8}$/, "");
  s = s.replace(/_/g, " ");
  return s.length > 64 ? s.slice(0, 64) + "…" : s;
}

// ---- summary view: cards + test×client matrix ----
function clientTotals(n) {
  const t = { pass: 0, out: 0, ano: 0, exc: 0 };
  results.forEach(r => {
    if ((r.excluded_clients || []).includes(n)) { t.exc++; return; }
    const divs = (r.divergences || []).filter(d => (d.client_results || {})[n] !== undefined);
    if (!divs.length) { if (r.status === "pass") t.pass++; return; }
    if (divs.some(d => isOutlier(d, n))) t.out++;
    else if (divs.every(d => verdictOf(d, n) === "other")) t.ano++;
  });
  const run = t.pass + t.out + t.ano;
  t.rate = run ? t.pass / run : 1;
  return t;
}
function clientCard(n) {
  const t = clientTotals(n);
  const st = t.out ? "out" : t.ano ? "ano" : (t.pass ? "pass" : "idle");
  const d = el("div", "ccard " + st);
  const head = el("div", "big");
  head.append(el("span", "dot " + st), n);
  d.append(head);
  const sub = el("div", "sub");
  sub.append(el("span", "p", t.pass + " pass"), " · ",
             el("span", "r", t.out + " outlier"), " · ",
             el("span", "a", t.ano + " anomalous"), " · ",
             el("span", "x", t.exc + " excluded"));
  d.append(sub);
  d.append(el("div", "sub", (t.rate * 100).toFixed(1) + "% agreement"));
  const bar = el("div", "minibar");
  const seg = (w, c) => { const s = el("div", c); s.style.width = (w * 100) + "%"; return s; };
  const run = t.pass + t.out + t.ano;
  if (run) bar.append(seg(t.pass / run, "g"), seg(t.out / run, "r"), seg(t.ano / run, "a"));
  else bar.append(seg(1, "x"));
  d.append(bar);
  d.title = "click to open client view for " + n;
  d.addEventListener("click", () => openClient(n));
  return d;
}
function renderSummary() {
  const out = document.getElementById("view-summary");
  out.textContent = "";
  const cards = el("div", "ccards");
  clientNames.forEach(n => cards.append(clientCard(n)));
  out.append(cards);
  const legend = el("div", "count");
  legend.append(el("span", "lg g", "● pass"), "  ",
                el("span", "lg r", "● outlier"), "  ",
                el("span", "lg a", "● anomalous"), "  ",
                el("span", "lg x", "● excluded"),
                " · card top bar shows worst status · click a card for a per-client focus");
  out.append(legend);
  out.append(el("h2", "sec", "Test results × clients"));
  const bar = el("div", "bar");
  const q = el("input");
  q.id = "q-sum"; q.type = "search"; q.placeholder = "filter by test id";
  const selCat = el("select"); selCat.id = "sel-sum-cat";
  selCat.append(new Option("any category", ""));
  [...new Set(results.map(r => r.category || "other"))].sort().forEach(c => selCat.append(new Option(c, c)));
  const selSt = el("select"); selSt.id = "sel-sum-status";
  selSt.append(new Option("any status", ""));
  ["pass", "divergent", "skipped", "error"].forEach(s => selSt.append(new Option(s, s)));
  bar.append(q, selCat, selSt);
  out.append(bar);
  const listOut = el("div");
  listOut.id = "sum-tests";
  out.append(listOut);
  q.addEventListener("input", renderSumTests);
  selCat.addEventListener("change", renderSumTests);
  selSt.addEventListener("change", renderSumTests);
  renderSumTests();
}
// expectedOf derives the expected verdict for a divergence: structured
// field first, then the description hint, then non-outlier consensus.
function expectedOf(d) {
  let exp = d.expected || null, expN = 0, derived = false;
  if (!exp && /want accept=(true|false)/.test(d.description || "")) {
    exp = /want accept=true/.test(d.description) ? "accept" : "reject";
  }
  if (!exp) {
    const outs = d.outlier_clients || [];
    const tally = {};
    Object.keys(d.client_results || {}).forEach(n => {
      if (outs.includes(n)) return;
      const v = d.client_results[n];
      tally[v] = (tally[v] || 0) + 1;
    });
    Object.keys(tally).forEach(v => { if (tally[v] > expN) { exp = v; expN = tally[v]; } });
    derived = !!exp;
  }
  return { exp, expN, derived };
}
function expRow(d) {
  const { exp, expN, derived } = expectedOf(d);
  const label = !exp ? "expected · unknown"
    : derived ? "expected · " + expN + " client" + (expN > 1 ? "s" : "") + " agree"
    : "expected";
  const row = el("div", "crrow inline isme");
  row.append(el("span", "n", label));
  row.append(el("span", "vc expect", exp || "?"));
  return row;
}
function vshort(v) { return v && v.startsWith("other:") ? "other" : v; }
// reasonOf extracts one client's failure reason: structured detail first,
// then the "other:<detail>" verdict suffix.
function reasonOf(d, n) {
  const det = (d.client_details || {})[n];
  if (det) return det.trim();
  const v = (d.client_results || {})[n] || "";
  return v.startsWith("other:") ? v.slice(6).trim() : "";
}
// conformanceRows tells the story in order: what was expected, who matched,
// who deviated, and why — identical reasons merged into one line.
function conformanceRows(d, me) {
  const { exp } = expectedOf(d);
  const names = Object.keys(d.client_results || {}).sort();
  const ok = [], bad = [];
  names.forEach(n => {
    const v = vshort(d.client_results[n]);
    const conform = exp ? conforms(v, exp) : !isOutlier(d, n);
    (conform ? ok : bad).push(n);
  });
  const wrap = el("div", "");
  const okRow = el("div", "crrow inline isme");
  okRow.append(el("span", "vc match", "✓ match (" + ok.length + ")"));
  const okChips = el("span", "clients left");
  ok.forEach(n => {
    let label = shortName(n);
    if (n === me) label += " (you)";
    const chip = el("span", "cchip", label);
    const r = reasonOf(d, n);
    if (r) chip.setAttribute("data-reason", r);
    okChips.append(chip);
  });
  okRow.append(okChips);
  wrap.append(okRow);
  if (bad.length) {
    const badRow = el("div", "crrow inline isout");
    badRow.append(el("span", "vc deviate", "▲ deviate (" + bad.length + ")"));
    const badChips = el("span", "clients left");
    bad.forEach(n => {
      let label = shortName(n);
      if (n === me) label += " (you)";
      const chip = el("span", "cchip bad", label);
      const r = reasonOf(d, n);
      const verdictTxt = r ? r : "No error detail was captured for this client — only its verdict was recorded.";
      chip.setAttribute("data-reason", (isOutlier(d, n) ? "outlier · " : "") + verdictTxt);
      badChips.append(chip);
    });
    badRow.append(badChips);
    wrap.append(badRow);
  }
  return wrap;
}
// stepsRowsAll renders one block per step: the expected verdict, one row for
// the conforming clients, and one row per distinct non-conforming verdict.
// Per-client rejection modes live in the chip tooltips, not as extra rows.
function stepsRowsAll(d, me) {
  const wrap = el("div", "");
  const n = d.steps.length;
  d.steps.forEach(st => {
    const names = Object.keys(st.client_results || {}).sort();
    const ok = names.filter(x => conforms(st.client_results[x], st.expected));
    const badBy = {};
    names.filter(x => !conforms(st.client_results[x], st.expected)).forEach(x => {
      const got = vshort(st.client_results[x]) || "?";
      (badBy[got] = badBy[got] || []).push(x);
    });
    const head = el("div", "crrow inline isme stepsum");
    const caret = el("span", "caret", "▸");
    head.append(caret);
    head.append(el("span", "n", "step " + st.index + "/" + n + " · " + st.label + (st.input ? " · " + st.input : "")));
    const badge = ok.length === names.length
      ? el("span", "vc match", "✓ " + ok.length + "/" + names.length)
      : el("span", "vc deviate", "✗ " + (names.length - ok.length) + "/" + names.length + " off-spec");
    head.append(badge);
    const body = el("div", "stepbody");
    // Expected-verdict line first, structurally identical to the group
    // rows below so the badge lines up with the group labels.
    const wline = el("div", "crrow inline isme");
    wline.append(el("span", "vc expect big", "want " + st.expected));
    body.append(wline);
    if (ok.length) {
      const line = el("div", "crrow inline isme");
      line.append(el("span", "vc match", "✓ " + st.expected + " (" + ok.length + ")"));
      line.append(chipsWithReason(ok.map(x => [x, st.client_results[x]]), d, me, st.expected));
      body.append(line);
    }
    Object.keys(badBy).sort().forEach(got => {
      const line = el("div", "crrow inline isout");
      line.append(el("span", "vc deviate", "▲ " + got + " (" + badBy[got].length + ")"));
      line.append(chipsWithReason(badBy[got].map(x => [x, st.client_results[x]]), d, me, st.expected));
      body.append(line);
    });
    body.style.display = "none";
    head.addEventListener("click", () => {
      const open = body.style.display === "none";
      body.style.display = open ? "" : "none";
      caret.textContent = open ? "▾" : "▸";
    });
    wrap.append(head);
    wrap.append(body);
  });
  return wrap;
}
// humanVerdict turns a raw verdict ("accept", "reject:dial_failed",
// "error_chunk:0x01") into a readable phrase.
function humanVerdict(v) {
  if (v === undefined || v === null) return "no result recorded (sequence incomplete)";
  if (v === "accept") return "accepted";
  if (v === "reject") return "rejected";
  if (String(v).startsWith("reject:")) {
    const r = String(v).slice(7);
    const map = {
      "dial_failed": "rejected — could not connect (dial failed)",
      "connection_error": "rejected — connection error",
      "reset": "rejected — stream reset by peer",
      "timeout": "rejected — read timeout",
      "error_chunk:0x01": "rejected — error chunk 0x01",
      "error_chunk:0x02": "rejected — error chunk 0x02",
      "error_chunk:0x03": "rejected — error chunk 0x03",
    };
    return map[r] || ("rejected — " + r);
  }
  if (String(v).startsWith("other:")) return "other behavior — " + String(v).slice(6);
  return String(v);
}
// chipsWithReason renders client chips whose hover bubble shows the raw
// verdict (e.g. the concrete reject mode) behind the grouped label.
function chipsWithReason(pairs, d, me, want) {
  const wrap = el("span", "clients left");
  pairs.forEach(([x, got]) => {
    let label = shortName(x);
    if (x === me) label += " (you)";
    const chip = el("span", "cchip", label);
    // A group that matches the expectation already says so on its label;
    // the hover explanation only earns its place on deviating groups.
    if (!(want && got === want)) {
      const det = reasonOf(d, x);
      let txt = (isOutlier(d, x) ? "outlier · " : "") + humanVerdict(got);
      if (want) txt += " — want " + want;
      if (det && det !== got) txt += "\n" + det;
      chip.setAttribute("data-reason", txt);
    }
    wrap.append(chip);
  });
  return wrap;
}
// stepsTableClient renders a per-step expected-vs-actual focus on one client.
function stepsTableClient(d, me) {
  const wrap = el("div", "");
  const n = d.steps.length;
  d.steps.forEach(st => {
    const mine = (st.client_results || {})[me];
    const bad = mine !== st.expected;
    const row = el("div", "crrow " + (bad ? "isout" : "isme"));
    row.append(el("span", "n", "step " + st.index + "/" + n + " · " + st.label + (st.input ? " · " + st.input : "")));
    const right = el("span", "");
    right.append(el("span", "vc expect", "want " + st.expected));
    right.append(el("span", "vc " + (bad ? "deviate" : "match"), (bad ? "▲ " : "✓ ") + (vshort(mine) || "—")));
    row.append(right);
    wrap.append(row);
  });
  return wrap;
}
// knownDetail renders an allowlisted (implementation-specific) divergence
// neutrally: no expected/outlier framing, values for reference only.
function knownDetail(d) {
  const w = el("div", "divdetail");
  w.append(el("div", "ev", "known implementation difference — this field is per-node by design and not comparable across clients; values listed for reference only."));
  const groups = {};
  Object.keys(d.client_results || {}).forEach(n => {
    const v = d.client_results[n];
    const vs = v && v.startsWith("other:") ? "other" : v;
    (groups[vs] = groups[vs] || []).push(n);
  });
  Object.keys(groups).sort().forEach(v => {
    const names = groups[v].sort();
    const row = el("div", "crrow isme");
    row.append(el("span", "vc", v + " (" + names.length + ")"));
    row.append(el("span", "n", names.map(shortName).join(", ")));
    w.append(row);
  });
  return w;
}
function divDetail(d, me) {
  const w = el("div", "divdetail");
  if (knownIds.has(d.test_id)) { w.append(knownDetail(d)); return w; }
  if (d.input) w.append(el("div", "rules", "input: " + d.input));
  if (d.steps && d.steps.length) {
    w.append(stepsTableClient(d, me));
  } else {
    w.append(expRow(d));
    w.append(conformanceRows(d, me));
  }
  return w;
}
// divDetailGlobal renders a divergence on the summary page: same content as
// the client view but without any "current client" focus.
function divDetailGlobal(d) {
  const w = el("div", "divdetail");
  if (knownIds.has(d.test_id)) { w.append(knownDetail(d)); return w; }
  if (d.input) w.append(el("div", "rules", "input: " + d.input));
  if (d.steps && d.steps.length) {
    w.append(stepsRowsAll(d, null));
  } else {
    w.append(expRow(d));
    w.append(conformanceRows(d, null));
  }
  return w;
}
// reproduceBlock renders the per-test rerun command as a collapsed row;
// clicking expands the actual command.
function reproduceBlock(r) {
  const wrap = el("div", "");
  const head = el("div", "crrow inline isme stepsum");
  const caret = el("span", "caret", "▸");
  head.append(caret, el("span", "n", "reproduce command"));
  const cmd = el("pre", "cmdblock", reproduceCmd(r) + "\n# local nodes: … -env static -config clients.yaml -test '" + r.test_id + "'");
  cmd.style.display = "none";
  head.addEventListener("click", () => {
    const open = cmd.style.display === "none";
    cmd.style.display = open ? "" : "none";
    caret.textContent = open ? "▾" : "▸";
  });
  wrap.append(head);
  wrap.append(cmd);
  return wrap;
}
function testDetailBody(r) {
  const body = el("div");
  if (r.description) body.append(el("div", "ev", r.description));
  if (r.status === "divergent" || r.status === "error") {
    body.append(reproduceBlock(r));
  }
  if (r.status === "skipped") body.append(el("div", "ev", r.skip_reason || "skipped"));
  else if (r.status === "error") body.append(el("div", "ev", r.skip_reason || "error"));
  else if (r.status === "pass") body.append(el("div", "ev", "passed · all clients agree"));
  (r.divergences || []).forEach(x => body.append(divDetailGlobal(x)));
  if ((r.excluded_clients || []).length) body.append(el("div", "ev", "excluded: " + r.excluded_clients.join(", ")));
  return body;
}
// matrix: rows = tests, columns = clients, cell = that client's outcome.
// conforms reports whether one client verdict satisfies an expected
// verdict: exact match, or any "reject:<reason>" satisfies "reject" — the
// rejection mode is evidence, not a different verdict.
function conforms(mine, exp) {
  if (mine === undefined || mine === null) return false;
  if (mine === exp) return true;
  if (exp === "reject" && String(mine).startsWith("reject")) return true;
  return false;
}
function matrixCell(r, n) {
  const td = el("td");
  const known = knownIds.has(r.test_id);
  if ((r.excluded_clients || []).includes(n)) {
    td.append(el("span", "mc x", "⏸"));
    td.title = n + ": excluded";
    return td;
  }
  if (r.status === "pass") { td.append(el("span", "mc ok", "✓")); td.title = n + ": passed"; return td; }
  if (r.status !== "divergent") { td.append(el("span", "mc x", "·")); return td; }
  const divs = r.divergences || [];
  const eo = expectedOf(divs[0] || {});
  const isOut = divs.some(d => isOutlier(d, n));
  let v = null;
  divs.forEach(dv => { if ((dv.client_results || {})[n] !== undefined) v = dv.client_results[n]; });
  const vs = v && v.startsWith("other:") ? "other" : v;
  let cls = "x", t2 = "—";
  if (v != null) {
    if (known) { cls = "x"; t2 = vs; }
    else if (isOut) { cls = "bad"; t2 = "✗"; }
    else if (eo.exp && conforms(vs, eo.exp)) { cls = "ok"; t2 = "✓"; }
    else { cls = "warn"; t2 = "✗"; }
  }
  const sp = el("span", "mc " + cls);
  sp.textContent = t2;
  if (v) {
    const fails = [];
    divs.forEach(d => {
      const exp = expectedOf(d).exp;
      const mine = (d.client_results || {})[n];
      if (mine === undefined) return;
      const mineS = mine.startsWith("other:") ? "other" : mine;
      if (!(isOutlier(d, n) || (exp && mineS !== exp))) return;
      if (d.steps && d.steps.length) {
        let listed = false;
        d.steps.forEach(st => {
          const got = (st.client_results || {})[n];
          if (got === undefined) {
            fails.push("✗ " + (st.label || "step " + st.index) + ": " + humanVerdict(undefined) + ", want " + st.expected);
            listed = true;
            return;
          }
          if (!conforms(got, st.expected)) {
            fails.push("✗ " + (st.label || "step " + st.index) + ": " + humanVerdict(got) + ", want " + st.expected);
            listed = true;
          }
        });
        if (!listed) fails.push("✗ matched every step's expected verdict — flagged " + (isOutlier(d, n) ? "as outlier by consensus" : "off-consensus"));
      } else if (exp && /^[aro]+$/.test(exp) && mineS.length === exp.length && mineS !== exp) {
        // legacy data without steps: decode position-by-position against the
        // consensus sequence, naming steps from the test id when possible.
        const parts = (d.test_id || "").split(".");
        const si = parts.indexOf("seq");
        const labels = si >= 0 ? parts.slice(si + 2) : [];
        const dec = c => c === "a" ? "accept" : c === "r" ? "reject" : "other";
        for (let i = 0; i < mineS.length; i++) {
          if (mineS[i] === exp[i]) continue;
          const label = labels[i] ? labels[i] + " (step " + (i + 1) + "/" + mineS.length + ")" : "step " + (i + 1) + "/" + mineS.length;
          fails.push("✗ " + label + ": got " + dec(mineS[i]) + ", consensus " + dec(exp[i]));
        }
        if (!fails.length) fails.push("✗ verdict " + mineS + ", consensus " + exp);
      } else {
        const r = reasonOf(d, n);
        fails.push("✗ " + (r || (humanVerdict(mineS) + ", want " + (exp || "?"))));
      }
    });
    sp.setAttribute("data-reason", n + (fails.length ? "\n" + fails.join("\n") : " · matched the expected verdict on every step"));
  }
  td.append(sp);
  return td;
}
function matrixRow(r) {
  const known = knownIds.has(r.test_id);
  const tr = el("tr", "mrow");
  const td = el("td", "mtest");
  const st = r.status === "pass" ? "pass" : r.status === "divergent" ? (known ? "idle" : "out") : "idle";
  const stat = el("span", "mstat");
  const caret = el("span", "caret", "▸");
  stat.append(caret, el("span", "dot " + st), el("span", "tid", r.test_id));
  let rules = r.spec_rule_ids || [];
  if (!rules.length) {
    const d0 = (r.divergences || [])[0] || {};
    rules = d0.spec_rule_ids || [];
  }
  if (rules.length) {
    const rw = el("span", "mrules");
    rules.forEach(id => rw.append(specChip(id, id + " ⓘ")));
    stat.append(rw);
  }
  td.append(stat);
  if (known) td.append(chip("st-skipped", "known"));
  const divs = r.divergences || [];
  if (r.status === "divergent" && !known) {
    const sev = (function () {
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      let best = null;
      divs.forEach(d => { if (!best || order.indexOf(d.severity) < order.indexOf(best)) best = d.severity; });
      return best;
    })();
    if (sev) td.append(chip("sev-" + sev, sev));
  }
  tr.append(td);
  clientNames.forEach(n => tr.append(matrixCell(r, n)));
  const dr = el("tr", "mdetail");
  const dc = el("td");
  dc.colSpan = clientNames.length + 1;
  const box = el("div", "detailbox");
  box.append(testDetailBody(r));
  dc.append(box);
  dr.append(dc);
  tr.addEventListener("click", () => {
    const open = dr.classList.toggle("open");
    tr.classList.toggle("open", open);
    caret.textContent = open ? "▾" : "▸";
  });
  return { tr, dr };
}
function renderSumTests() {
  const out = document.getElementById("sum-tests");
  out.textContent = "";
  const q = document.getElementById("q-sum").value;
  const cat = document.getElementById("sel-sum-cat").value;
  const st = document.getElementById("sel-sum-status").value;
  const list = results.filter(r =>
    match(r.test_id + " " + (r.skip_reason || ""), q) && (!cat || r.category === cat) && (!st || r.status === st));
  out.append(el("div", "count", list.length + " of " + results.length + " test(s) · click a row for per-client detail"));
  out.append(el("div", "count", "legend: ✓ matches expected · ✗ red = outlier (minority deviator) · ✗ gold = off-spec but majority · hover a cell for the failing steps"));
  if (!list.length) { out.append(el("div", "empty", "no tests match")); return; }
  const groups = new Map();
  list.forEach(r => {
    const k = r.category || "other";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  });
  [...groups.keys()].sort().forEach(cat2 => {
    const rows = groups.get(cat2);
    const divN = rows.filter(r => r.status === "divergent").length;
    const det = el("details", "group");
    const sum = el("summary");
    sum.append(el("span", "tid", cat2), el("span", "cnt", "(" + rows.length + " tests · " + divN + " divergent)"));
    det.append(sum);
    const t = el("table", "matrix matrix-sum");
    const thead = el("thead");
    const hr = el("tr");
    hr.append(el("th", null, "test"));
    clientNames.forEach(n => hr.append(el("th", null, shortName(n))));
    thead.append(hr);
    t.append(thead);
    const tb = el("tbody");
    rows.sort((a, b) => (a.test_id || "").localeCompare(b.test_id || "")).forEach(r => {
      const m = matrixRow(r);
      tb.append(m.tr, m.dr);
    });
    t.append(tb);
    det.append(t);
    out.append(det);
  });
}

// ---- client view ----
let currentClient = "";
let clientView = "oa";
const CLIENT_VIEWS = [["oa", "Issues"], ["pass", "Pass"], ["exc", "Excluded"]];
function clientItems(me, q) {
  const oa = new Map();
  const pass = [], exc = [];
  results.forEach(r => {
    if (!match(r.test_id + " " + (r.skip_reason || ""), q)) return;
    if ((r.excluded_clients || []).includes(me)) { exc.push({ r, divs: [] }); return; }
    const rel = (r.divergences || []).filter(d => (d.client_results || {})[me] !== undefined);
    const failed = rel.filter(d => isOutlier(d, me) || verdictOf(d, me) === "other");
    if (failed.length) {
      const byType = new Map();
      failed.forEach(d => {
        const k = d.type || "other";
        if (!byType.has(k)) byType.set(k, []);
        byType.get(k).push(d);
      });
      [...byType.keys()].forEach(k => {
        const divs = byType.get(k);
        const mark = divs.some(d => isOutlier(d, me)) ? "outlier" : "anomalous";
        if (!oa.has(k)) oa.set(k, []);
        oa.get(k).push({ r, type: k, divs, mark });
      });
      return;
    }
    if (r.status === "pass") pass.push({ r, divs: [] });
  });
  return { oa, pass, exc };
}
function itemCard(item, me, kind) {
  const r = item.r, divs = item.divs || [];
  const d = el("details", "group");
  const sum = el("summary");
  if (item.mark) sum.append(el("span", "dot " + (item.mark === "outlier" ? (knownIds.has(r.test_id) ? "idle" : "out") : "ano")));
  if (knownIds.has(r.test_id)) sum.append(chip("st-skipped", "known"));
  sum.append(el("span", "tid", r.test_id));
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  let sev = null;
  divs.forEach(x => { if (!sev || order.indexOf(x.severity) < order.indexOf(sev)) sev = x.severity; });
  if (sev) sum.append(chip("sev-" + sev, sev));
  d.append(sum);
  const body = el("div", "body");
  if (r.description) body.append(el("div", "ev", r.description));
  if (kind === "oa") {
    body.append(reproduceBlock(r));
  }
  if (kind === "pass") body.append(el("div", "ev", "passed"));
  else if (kind === "exc") body.append(el("div", "ev", r.skip_reason || "excluded"));
  else if (!divs.length) body.append(el("div", "ev", "no client details"));
  else divs.forEach(x => body.append(divDetail(x, me)));
  if (r.elapsed) body.append(el("div", "ev", "elapsed: " + r.elapsed));
  d.append(body);
  return d;
}
function typeGroup(title, items, me, kind) {
  const g = el("details", "group");
  const sum = el("summary");
  sum.append(el("span", "tid", title), el("span", "cnt", "(" + items.length + ")"));
  g.append(sum);
  const body = el("div", "body");
  items.forEach(item => body.append(itemCard(item, me, kind)));
  g.append(body);
  return g;
}
function markBreakdown(rows) {
  const o = rows.filter(x => x.mark === "outlier").length;
  const a = rows.length - o;
  if (!o && !a) return null;
  const sp = el("span", "cnt");
  const parts = [];
  if (o) parts.push([o + " outlier", "lg r"]);
  if (a) parts.push([a + " anomalous", "lg a"]);
  parts.forEach((p, i) => {
    if (i) sp.append(" · ");
    sp.append(el("span", p[1], p[0]));
  });
  return sp;
}
function renderClient() {
  const me = currentClient;
  const crumbs = document.getElementById("client-crumbs");
  crumbs.textContent = "";
  const back = el("button", "crumblink", "Summary");
  back.addEventListener("click", () => tab("summary"));
  crumbs.append(back, el("span", "crumbsep", "/"));
  if (me) {
    const t = clientTotals(me);
    const st = t.out ? "out" : t.ano ? "ano" : (t.pass ? "pass" : "idle");
    const here = el("span", "crumbhere");
    here.append(el("span", "dot " + st), me);
    crumbs.append(here);
  }
  const q = document.getElementById("q-client").value;
  const out = document.getElementById("client-out");
  out.textContent = "";
  const tabBar = el("div", "bar");
  CLIENT_VIEWS.forEach(([k, label]) => {
    const b = el("button", "tab sub" + (clientView === k ? " active" : ""), label);
    b.addEventListener("click", () => { clientView = k; renderClient(); });
    tabBar.append(b);
  });
  out.append(tabBar);
  const items = clientItems(me, q);
  const t = clientTotals(me);
  let any = false;
  const add = (title, rows, kind, breakdown) => {
    if (!rows.length) return;
    any = true;
    out.append(typeGroup(title, rows, me, kind, breakdown));
  };
  if (clientView === "oa") {
    const head = el("div", "count");
    head.append(el("span", "lg r", t.out + " outlier"), " · ",
                el("span", "lg a", t.ano + " anomalous"), " · " + (t.out + t.ano) + " test(s)");
    out.append(head);
    [...items.oa.keys()].sort().forEach(k => {
      const rows = items.oa.get(k);
      add(k, rows, "oa", markBreakdown(rows));
    });
  } else {
    const src = clientView === "pass" ? items.pass : items.exc;
    if (src.length) out.append(el("div", "count", src.length + " test(s)"));
    const g = new Map();
    src.forEach(x => {
      const k = x.r.category || "other";
      if (!g.has(k)) g.set(k, []);
      g.get(k).push(x);
    });
    [...g.keys()].sort().forEach(c => add(c, g.get(c), clientView));
  }
  if (!any) out.append(el("div", "empty", "no tests match"));
}
let clientTestIds = [];
function collectTestIds(me) {
  const items = clientItems(me, "");
  const ids = new Set();
  items.pass.forEach(x => ids.add(x.r.test_id));
  items.exc.forEach(x => ids.add(x.r.test_id));
  [...items.oa.values()].forEach(rows => rows.forEach(x => ids.add(x.r.test_id)));
  clientTestIds = [...ids].sort();
}
(function () {
  const input = document.getElementById("q-client");
  const pop = document.getElementById("ac-pop");
  function renderAc() {
    const q = input.value.trim().toLowerCase();
    pop.textContent = "";
    if (!q) { pop.style.display = "none"; return; }
    const matches = clientTestIds.filter(id => id.toLowerCase().includes(q)).slice(0, 8);
    if (!matches.length) { pop.style.display = "none"; return; }
    matches.forEach(id => {
      const it = el("div", "acitem", id);
      it.addEventListener("mousedown", e => {
        e.preventDefault();
        input.value = id;
        pop.style.display = "none";
        renderClient();
      });
      pop.append(it);
    });
    pop.style.display = "block";
  }
  input.addEventListener("input", () => { renderAc(); renderClient(); });
  input.addEventListener("blur", () => setTimeout(() => { pop.style.display = "none"; }, 120));
  input.addEventListener("keydown", e => { if (e.key === "Escape") pop.style.display = "none"; });
})();
function openClient(n) {
  currentClient = n;
  clientView = "oa";
  collectTestIds(n);
  tab("client");
  renderClient();
}

// ---- findings view ----
const selSev = document.getElementById("sel-sev");
const sevs = [];
findings.forEach(f => { if (f.severity && !sevs.includes(f.severity)) sevs.push(f.severity); });
sevs.sort().forEach(sv => selSev.append(new Option(sv, sv)));
function divergenceCard(d, selectedClient) {
  const c = el("div", "card");
  const head = el("div", "fhead");
  head.append(chip("sev-" + d.severity, d.severity || "?"), chip(null, d.type || "?"));
  if (d.test_id) head.append(el("span", "tid", d.test_id));
  c.append(head);
  c.append(el("div", "cause", d.description || ""));
  if (d.input) c.append(el("div", "rules", "input: " + d.input));
  if (d.expected) c.append(el("div", "ev", "expected: " + d.expected));
  const outs = d.outlier_clients || [];
  if (outs.length) {
    const o = el("div", "outs", "outliers: ");
    o.append(el("b", null, outs.join(", ")));
    c.append(o);
  }
  const sl = specLine(d.spec_rule_ids, d.knowledge_ids);
  if (sl) c.append(sl);
  const det = el("div", "detail");
  if (d.steps && d.steps.length) {
    const names = Object.keys(d.client_results || {}).sort();
    const t = el("table", "matrix");
    const hr = el("tr");
    hr.append(el("th", null, "step"));
    names.forEach(n => hr.append(el("th", null, shortName(n))));
    hr.append(el("th", null, "expected"));
    t.append(hr);
    d.steps.forEach(st => {
      const row = el("tr");
      row.append(el("td", null, st.index + ". " + st.label + (st.input ? " · " + st.input : "")));
      names.forEach(n => {
        const v = (st.client_results || {})[n];
        const bad = v !== st.expected;
        const td = el("td", bad ? "bad" : "ok", vshort(v) || "—");
        if (v && v.startsWith("other:")) td.title = v;
        row.append(td);
      });
      row.append(el("td", "exp", st.expected));
      t.append(row);
    });
    det.append(t);
  } else {
    Object.keys(d.client_results || {}).sort().forEach(n => {
      const row = el("div", "cr" + (isOutlier(d, n) ? " isOut" : "") + (n === selectedClient ? " isMe" : ""));
      row.append(el("span", "n", n + (isOutlier(d, n) ? "  ◄ outlier" : "") + (n === selectedClient ? "  (selected)" : "")),
                 el("span", "v", d.client_results[n]));
      det.append(row);
      const cd = (d.client_details || {})[n];
      if (cd) det.append(el("div", "ev", "↳ " + n + ": " + cd));
    });
  }
  c.append(det);
  c.classList.add("click");
  c.addEventListener("click", () => det.classList.toggle("open"));
  return c;
}
function findingCard(f) {
  const c = el("div", "card");
  const head = el("div", "fhead");
  head.append(el("span", "fid", f.id || ""));
  head.append(chip("sev-" + f.severity, f.severity || "?"), chip(null, f.type || "?"));
  if (f.evidence_count) head.append(chip(null, "evidence ×" + f.evidence_count));
  if (f.suppressed) head.append(chip("sup", "suppressed"));
  c.append(head);
  c.append(el("div", "cause", f.root_cause || ""));
  const outs = f.outlier_clients || [];
  if (outs.length) {
    const o = el("div", "outs", "outliers: ");
    o.append(el("b", null, outs.join(", ")));
    c.append(o);
  }
  if (f.suppress_reason) c.append(el("div", "reason", f.suppress_reason));
  const det = el("div", "detail");
  (f.evidence || []).forEach(d => det.append(divergenceCard(d, currentClient)));
  if (!(f.evidence || []).length) det.append(el("div", "ev", "no evidence divergences recorded"));
  c.append(det);
  c.classList.add("click");
  c.addEventListener("click", () => det.classList.toggle("open"));
  return c;
}
function groupRows(rows, keyOf) {
  const g = new Map();
  rows.forEach(r => {
    const k = keyOf(r) || "other";
    if (!g.has(k)) g.set(k, []);
    g.get(k).push(r);
  });
  return g;
}
function appendGroups(out, groups, buildRow) {
  let first = true;
  [...groups.keys()].sort().forEach(cat => {
    const rows = groups.get(cat);
    const d = el("details", "group");
    if (first) { d.open = true; first = false; }
    const sum = el("summary");
    sum.append(el("span", "tid", cat), el("span", "cnt", "(" + rows.length + ")"));
    d.append(sum);
    const body = el("div", "body");
    rows.forEach(row => body.append(buildRow(row)));
    d.append(body);
    out.append(d);
  });
}
function renderFindings() {
  const q = document.getElementById("q-find").value;
  const sv = selSev.value;
  const sup = document.getElementById("sel-sup").value;
  const out = document.getElementById("findings-out");
  out.textContent = "";
  const list = findings.filter(f => {
    if (sv && f.severity !== sv) return false;
    if (sup === "active" && f.suppressed) return false;
    if (sup === "sup" && !f.suppressed) return false;
    const hay = [f.id, f.root_cause, (f.outlier_clients || []).join(" ")]
      .concat((f.evidence || []).flatMap(e => [e.test_id || "", (e.spec_rule_ids || []).join(" ")])).join(" ");
    return match(hay, q);
  });
  out.append(el("div", "count", list.length + " of " + findings.length + " finding(s)"));
  if (!list.length) { out.append(el("div", "empty", "no findings match")); return; }
  appendGroups(out, groupRows(list, f => {
    const ev = (f.evidence || [])[0];
    return (ev && ev.category) || "other";
  }), f => findingCard(f));
}
document.getElementById("q-find").addEventListener("input", renderFindings);
selSev.addEventListener("change", renderFindings);
document.getElementById("sel-sup").addEventListener("change", renderFindings);

// ---- top tabs ----
function tab(name) {
  currentTab = name;
  document.querySelector(".tabs").style.display = name === "client" ? "none" : "";
  document.getElementById("tab-summary").classList.toggle("active", name === "summary");
  document.getElementById("tab-findings").classList.toggle("active", name === "findings");
  document.getElementById("tab-history").classList.toggle("active", name === "history");
  document.getElementById("view-summary").style.display = name === "summary" ? "" : "none";
  document.getElementById("view-client").style.display = name === "client" ? "" : "none";
  document.getElementById("view-findings").style.display = name === "findings" ? "" : "none";
  document.getElementById("view-history").style.display = name === "history" ? "" : "none";
}
document.getElementById("tab-summary").addEventListener("click", () => tab("summary"));
document.getElementById("tab-findings").addEventListener("click", () => tab("findings"));
document.getElementById("tab-history").addEventListener("click", () => tab("history"));

// ---- history tab: pick one of the embedded runs, or load a json from disk ----
function renderHistory() {
  const out = document.getElementById("view-history");
  out.textContent = "";
  runs.forEach((r, i) => {
    const m = r.meta || {};
    const sm = m.summary || {};
    const card = el("div", "card click" + (i === currentRun ? " active" : ""));
    const head = el("div", "fhead");
    head.append(el("span", "fid", (m.started_at || "?").replace("T", " ").slice(0, 16)));
    head.append(chip(i === currentRun ? "st-pass" : "", i === currentRun ? "current" : "switch"));
    if (m.clients) head.append(chip("", m.clients));
    head.append(chip(sm.divergent ? "st-divergent" : "st-pass",
      (sm.passed != null ? sm.passed : "?") + "/" + (sm.total != null ? sm.total : "?") + " passed" +
      (sm.divergent ? ", " + sm.divergent + " div" : "")));
    if (m.seed != null) head.append(chip("", "seed " + m.seed));
    card.append(head);
    if (m.command) card.append(el("div", "rules", m.command));
    card.title = r.report ? "show this run" : "archived summary only — click to load its report json from disk";
    card.addEventListener("click", () => {
      if (r.report) { applyRun(i); tab("summary"); return; }
      loadRunFromFile();
    });
    out.append(card);
  });
}

function loadRunFromFile() {
  let inp = document.getElementById("hist-file");
  if (!inp) {
    inp = el("input");
    inp.type = "file";
    inp.accept = ".json,application/json";
    inp.id = "hist-file";
    inp.style.display = "none";
    document.body.append(inp);
    inp.addEventListener("change", () => {
      const f = inp.files[0];
      if (!f) return;
      f.text().then(txt => {
        const loaded = JSON.parse(txt);
        runs.push({ meta: {}, report: loaded, findings: [] });
        applyRun(runs.length - 1);
      }).catch(() => alert("invalid report json"));
      inp.value = "";
    });
  }
  inp.click();
}

applyRun(currentRun);
</script>
</body>
</html>
`))
