#!/usr/bin/env bash
#
# implement.sh — run PRD tasks through a fresh Claude Code session, one per task.
#
# Each task gets its own session (no --continue, no --resume): the task text plus
# prds/CONTEXT.md is the whole handover, and prds/reports/task-NN.json is the whole
# result. This script owns the tracking files; the agent only writes its report.
#
# Refuses to start a task when less than --min-remaining percent of the
# subscription budget is left, and says when to run it again.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRDS="$ROOT/prds"
PRD_JSON="$PRDS/prd.json"
CONTEXT="$PRDS/CONTEXT.md"
REPORTS="$PRDS/reports"
LOGS="$PRDS/logs"
PROGRESS="$PRDS/progress.txt"
SESSION="$PRDS/session.json"
MEMORY="$PRDS/session-memory.json"
CREDS="${CLAUDE_CREDENTIALS:-$HOME/.claude/.credentials.json}"
USAGE_URL="https://api.anthropic.com/api/oauth/usage"

# --- defaults ---------------------------------------------------------------
ITERATIONS=1
TASK_INDEX=""
MIN_REMAINING=10          # refuse to start below this many percent remaining
MODEL="${IMPLEMENT_MODEL:-}"
EFFORT="${IMPLEMENT_EFFORT:-}"
PERMISSION_MODE="bypassPermissions"
TIMEOUT_SECONDS=0         # 0 = no timeout
DRY_RUN=0
SKIP_BUDGET=0
RETRY_FAILED=0

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; grn=$'\033[32m'; ylw=$'\033[33m'; rst=$'\033[0m'
[ -t 1 ] || { bold=""; dim=""; red=""; grn=""; ylw=""; rst=""; }

say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$bold" "$rst" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$ylw" "$rst" "$*" >&2; }
die()  { printf '%s[error]%s %s\n' "$red" "$rst" "$*" >&2; exit 1; }

usage() {
  cat <<'HELP_END'
implement.sh — run PRD tasks through fresh Claude Code sessions, one per task.

USAGE
    ./implement.sh [options]

OPTIONS
    -n, --iterations N       Maximum tasks to run in this invocation (default: 1).
                             The loop also stops on the first non-completed task,
                             when tasks run out, or when the budget runs low.
    -t, --task INDEX         Run one specific task index instead of the next
                             unfinished one. Implies --iterations 1.
    -m, --model NAME         Model for the session (e.g. opus, sonnet). Default:
                             whatever Claude Code is configured to use.
    -e, --effort LEVEL       Effort level: low | medium | high | xhigh | max.
        --permission-mode M  Permission mode (default: bypassPermissions, which is
                             what makes an unattended run possible). Use
                             acceptEdits to keep prompts for non-edit tools.
        --min-remaining PCT  Refuse to start a task below this much remaining
                             budget (default: 10).
        --timeout SECONDS    Abort a single task's session after this long
                             (default: no limit).
        --retry-failed       Also pick up tasks whose last report was failed or
                             blocked. By default those are skipped.
        --no-budget-check    Skip the budget gate entirely. Use knowingly.
        --dry-run            Print the command and the prompt, run nothing.
    -l, --list               Show every task and its state, then exit.
    -s, --status             Show budget and progress, then exit.
    -h, --help               This text.

EXIT CODES
    0  all requested tasks completed
    2  a task ended blocked, partial or failed (loop stopped)
    3  budget below the threshold — nothing was started; message says when to retry
    4  no unfinished tasks left
    1  configuration or environment error

EXAMPLES
    ./implement.sh --status                 # what is left, and how much budget
    ./implement.sh -n 5                     # run up to five tasks
    ./implement.sh -t 12 -e high            # redo task 12 at high effort
    ./implement.sh -n 3 --min-remaining 25  # leave a bigger reserve
HELP_END
}

# --- argument parsing -------------------------------------------------------
MODE="run"
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--iterations)     ITERATIONS="${2:?}"; shift 2 ;;
    -t|--task)           TASK_INDEX="${2:?}"; ITERATIONS=1; shift 2 ;;
    -m|--model)          MODEL="${2:?}"; shift 2 ;;
    -e|--effort)         EFFORT="${2:?}"; shift 2 ;;
    --permission-mode)   PERMISSION_MODE="${2:?}"; shift 2 ;;
    --min-remaining)     MIN_REMAINING="${2:?}"; shift 2 ;;
    --timeout)           TIMEOUT_SECONDS="${2:?}"; shift 2 ;;
    --retry-failed)      RETRY_FAILED=1; shift ;;
    --no-budget-check)   SKIP_BUDGET=1; shift ;;
    --dry-run)           DRY_RUN=1; shift ;;
    -l|--list)           MODE="list"; shift ;;
    -s|--status)         MODE="status"; shift ;;
    -h|--help)           usage; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
done

case "$ITERATIONS" in ''|*[!0-9]*) die "--iterations must be a positive integer" ;; esac
[ "$ITERATIONS" -ge 1 ] || die "--iterations must be at least 1"
case "$MIN_REMAINING" in ''|*[!0-9]*) die "--min-remaining must be an integer 0-100" ;; esac
if [ -n "$TASK_INDEX" ]; then
  case "$TASK_INDEX" in ''|*[!0-9]*) die "--task must be a non-negative integer" ;; esac
fi

command -v claude  >/dev/null 2>&1 || die "claude CLI not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
command -v curl    >/dev/null 2>&1 || die "curl not found on PATH"
[ -f "$PRD_JSON" ] || die "missing $PRD_JSON"
[ -f "$CONTEXT" ]  || die "missing $CONTEXT — the agent has no operating guide"
# Claude Code refuses bypassPermissions under uid 0 unless it is told it is
# already confined. This runner is meant for a throwaway container, so say so
# out loud rather than letting every session die with an empty log.
if [ "$PERMISSION_MODE" = "bypassPermissions" ] && [ "$(id -u)" -eq 0 ] \
   && [ -z "${IS_SANDBOX:-}" ]; then
  warn "running as root — setting IS_SANDBOX=1 so bypassPermissions is accepted."
  warn "only sound inside a disposable container; use --permission-mode acceptEdits otherwise."
  export IS_SANDBOX=1
fi

mkdir -p "$REPORTS" "$LOGS"
touch "$PROGRESS"

# --- budget -----------------------------------------------------------------
# The usage endpoint is itself rate-limited, so a good reading is cached briefly
# and a stale-but-recent reading is preferred over refusing to run.
USAGE_CACHE="$PRDS/.usage-cache.json"
USAGE_FRESH_SECONDS=120     # reuse a reading this new without asking again
USAGE_STALE_SECONDS=1800    # fall back to a reading this old if the call fails

# Prints "<remaining>|<binding limit>|<resets_at>|<human>|<source>"
# or      "unavailable|<reason>|||"
budget_probe() {
  local token http body cached
  cached="$(python3 - "$USAGE_CACHE" "$USAGE_FRESH_SECONDS" <<'PY'
import json, os, sys, time
p, ttl = sys.argv[1], int(sys.argv[2])
if os.path.exists(p):
    try:
        c = json.load(open(p))
        if time.time() - c["at"] <= ttl:
            print(c["line"] + "|cached")
    except Exception:
        pass
PY
)"
  if [ -n "$cached" ]; then printf '%s\n' "$cached"; return 0; fi

  if [ ! -f "$CREDS" ]; then
    printf 'unavailable|no credentials file at %s|||\n' "$CREDS"; return 0
  fi
  token="$(python3 -c "
import json
try: print(json.load(open('$CREDS')).get('claudeAiOauth',{}).get('accessToken',''))
except Exception: print('')
" 2>/dev/null)" || token=""
  if [ -z "$token" ]; then
    printf 'unavailable|no OAuth token (API-key auth, or not logged in)|||\n'; return 0
  fi

  body="$(curl -sS -m 20 -w $'\n%{http_code}' "$USAGE_URL" \
      -H "Authorization: Bearer $token" \
      -H "anthropic-beta: oauth-2025-04-20" \
      -H "Content-Type: application/json" 2>/dev/null)" || body=""
  http="${body##*$'\n'}"; body="${body%$'\n'*}"
  [ -n "$http" ] || http="000"

  python3 - "$body" "$http" "$USAGE_CACHE" "$USAGE_STALE_SECONDS" <<'PY'
import json, os, sys, time, datetime

body, http, cache, stale_ttl = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def fallback(reason):
    if os.path.exists(cache):
        try:
            c = json.load(open(cache))
            age = int(time.time() - c["at"])
            if age <= stale_ttl:
                print(f'{c["line"]}|cached {age//60}m ago, live check {reason}')
                return
        except Exception:
            pass
    print(f"unavailable|{reason}|||")

if http != "200":
    fallback(f"HTTP {http}" + (" (usage endpoint rate-limited — wait a minute)" if http == "429" else ""))
    raise SystemExit
try:
    d = json.loads(body)
except Exception:
    fallback("usage response was not JSON"); raise SystemExit

lims = d.get("limits") or []
if not lims:
    for key in ("five_hour", "seven_day"):
        b = d.get(key)
        if isinstance(b, dict) and b.get("utilization") is not None:
            lims.append({"kind": key, "percent": b["utilization"], "resets_at": b.get("resets_at")})
if not lims:
    fallback("usage response carried no limits"); raise SystemExit

worst = max(lims, key=lambda l: (l.get("percent") or 0))
remaining = max(0.0, 100.0 - float(worst.get("percent") or 0))
iso = worst.get("resets_at") or ""
human = ""
if iso:
    try:
        t = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
        mins = max(0, int((t - datetime.datetime.now(datetime.timezone.utc).astimezone()).total_seconds() // 60))
        human = f"{t:%Y-%m-%d %H:%M %Z} (in {mins//60}h {mins%60}m)"
    except Exception:
        human = iso
kind = worst.get("kind") or "limit"
model = (worst.get("scope") or {}).get("model") or {}
if model.get("display_name"):
    kind += f" [{model['display_name']}]"

line = f"{remaining:.0f}|{kind}|{iso}|{human}"
try:
    json.dump({"at": time.time(), "line": line}, open(cache, "w"))
except Exception:
    pass
print(line + "|live")
PY
}

budget_report() {
  local probe remaining kind human source
  probe="$(budget_probe)"
  remaining="${probe%%|*}"
  kind="$(printf '%s' "$probe"   | cut -d'|' -f2)"
  human="$(printf '%s' "$probe"  | cut -d'|' -f4)"
  source="$(printf '%s' "$probe" | cut -d'|' -f5)"
  if [ "$remaining" = "unavailable" ]; then
    say "Budget:   ${ylw}unknown${rst} — $kind"
  else
    say "Budget:   ${remaining}% remaining (binding: $kind, resets $human) ${dim}[$source]${rst}"
  fi
}

# 0 = proceed, 3 = stop.
budget_gate() {
  if [ "$SKIP_BUDGET" -eq 1 ]; then
    warn "budget check skipped (--no-budget-check)"
    return 0
  fi
  local probe remaining kind human source
  probe="$(budget_probe)"
  remaining="${probe%%|*}"
  kind="$(printf '%s' "$probe"   | cut -d'|' -f2)"
  human="$(printf '%s' "$probe"  | cut -d'|' -f4)"
  source="$(printf '%s' "$probe" | cut -d'|' -f5)"

  if [ "$remaining" = "unavailable" ]; then
    say ""
    say "${red}${bold}Cannot verify the remaining budget.${rst}"
    say "  reason: $kind"
    say ""
    say "  ${bold}Nothing was started.${rst} A task begun without knowing the budget can"
    say "  ${dim}stop mid-edit and leave the tree half-changed.${rst}"
    say ""
    say "  Retry in a minute, or run with --no-budget-check to proceed anyway."
    return 3
  fi
  if [ "$remaining" -lt "$MIN_REMAINING" ]; then
    say ""
    say "${red}${bold}Budget too low to start a task.${rst}"
    say "  remaining:      ${remaining}%  (threshold: ${MIN_REMAINING}%)"
    say "  binding limit:  $kind"
    if [ -n "$human" ]; then
      say "  resets at:      $human"
      say ""
      say "  ${bold}Re-run ./implement.sh after $human.${rst}"
    else
      say ""
      say "  ${bold}Re-run ./implement.sh once the limit resets.${rst}"
    fi
    say ""
    say "  ${dim}Nothing was started, so no task is half-done.${rst}"
    return 3
  fi
  info "budget ok — ${remaining}% remaining (binding: $kind, resets $human) [$source]"
  return 0
}

# --- task selection ---------------------------------------------------------
pick_task() {   # -> "<index>" or "" ; honours TASK_INDEX and --retry-failed
  python3 - "$PRD_JSON" "$REPORTS" "${TASK_INDEX:-}" "$RETRY_FAILED" <<'PY'
import json, os, sys
prd, reports, want, retry = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
tasks = json.load(open(prd))["tasks"]
if want != "":
    i = int(want)
    if not (0 <= i < len(tasks)):
        sys.exit(f"task index {i} out of range 0..{len(tasks)-1}")
    print(i); raise SystemExit
for i, t in enumerate(tasks):
    if t.get("done"):
        continue
    rp = os.path.join(reports, f"task-{i:02d}.json")
    if os.path.exists(rp) and not retry:
        try:
            st = json.load(open(rp)).get("status")
        except Exception:
            st = None
        if st in ("failed", "blocked"):
            continue          # needs a human, or --retry-failed
    print(i); raise SystemExit
print("")
PY
}

task_field() { python3 -c "
import json,sys
t=json.load(open('$PRD_JSON'))['tasks'][int(sys.argv[1])]
v=t.get(sys.argv[2],'')
print('\n'.join('  - '+s for s in v) if isinstance(v,list) else v)
" "$1" "$2"; }

# --- prompt -----------------------------------------------------------------
build_prompt() {
  local idx="$1" nn title desc steps
  nn="$(printf '%02d' "$idx")"
  title="$(task_field "$idx" title)"
  desc="$(task_field "$idx" description)"
  steps="$(task_field "$idx" steps)"
  cat <<PROMPT
You are implementing exactly one task of the MAESTRO HELENA prototype, in a fresh
session. Work only on this task.

FIRST, read these, in this order:
  1. prds/CONTEXT.md          — your operating guide for this session. Binding.
  2. prds/session-memory.json — lessons and failed approaches from earlier sessions.
  3. concept/instruction.md   — the build rules (§2 invariants, §7 definition of done).
  4. The concept notes in concept/ that THIS task touches — not all of them.

Then check what already exists on disk before writing anything. Earlier tasks have
run and prds/reports/ holds their handovers, and the project already ships working
artifacts you must use rather than rebuild (CONTEXT.md §3):
  - bin/risingwave 3.0.3 and bin/blink 0.2.0, already built. \`source bin/env.sh\` first.
  - data/ingest/flow-sample.jsonl (62 real flow records) and data/threatfox/*.json
    (3375 ip:port, 433 domain, 287 url) — real shapes for design and for tests.
  - .venv/ — already created with uv venv (Python 3.12.14), no packages installed
    yet. Use it; \`uv add\` for dependencies, \`uv run\` for everything. Never pip,
    never a second venv.
  - .env — live tokens for the model endpoint, abuse.ch and VirusTotal. Use them to
    verify a connector really connects. Never print or commit a value.

=== TASK $idx ===
$title

$desc

Steps as written in the PRD (adjust to what you actually find; they are a plan
made earlier, not a licence to break an invariant):
$steps
=== END TASK ===

Rules that override the steps above, in order: concept/ > concept/instruction.md >
this task. If a step would break an invariant, do not do it — implement what is
compatible and record the conflict in your report.

Verify by execution, not by inspection: run \`uv run pytest -q\` (full suite at
least once) and any SQL against a throwaway engine instance. If the task touches
bin/, \`source bin/env.sh\` first.

FINALLY, and without exception, write your report to:
    prds/reports/task-$nn.json
using the schema in prds/CONTEXT.md §7. Set "status" honestly — completed,
partial, blocked or failed. A task with working code and no report is incomplete;
a "completed" with a failing test poisons every session after yours.

Do not edit prd.json, session.json, progress.txt or session-memory.json. This
runner owns them and reads your report.
PROMPT
}

# --- state updates ----------------------------------------------------------
record_result() {
  local idx="$1" status="$2" exitcode="$3" started="$4" ended="$5" sid="$6"
  python3 - "$PRD_JSON" "$SESSION" "$MEMORY" "$PROGRESS" "$REPORTS" \
            "$idx" "$status" "$exitcode" "$started" "$ended" "$sid" <<'PY'
import json, os, sys, datetime

prd, sess, mem, prog, reports, idx, status, code, started, ended, sid = sys.argv[1:12]
idx, code = int(idx), int(code)
started, ended = float(started), float(ended)
dur_ms = int((ended - started) * 1000)

with open(prd) as f: d = json.load(f)
task = d["tasks"][idx]

report = {}
rp = os.path.join(reports, f"task-{idx:02d}.json")
if os.path.exists(rp):
    try:
        with open(rp) as f: report = json.load(f)
    except Exception as e:
        report = {"status": "failed", "summary": f"report file is not valid JSON: {e}"}

# The report is the source of truth for status; the exit code only vetoes.
if status == "completed" and report.get("status") not in (None, "completed"):
    status = report["status"]
if code != 0 and status == "completed":
    status = "failed"

if status == "completed":
    task["done"] = True
    with open(prd, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False); f.write("\n")

# progress.txt — append-only human log
stamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
line = (f"[{stamp}] task {idx:02d} {status.upper():<9} "
        f"{dur_ms//1000}s exit={code} session={sid}\n"
        f"    {task['title']}\n")
summ = (report.get("summary") or "").strip()
if summ: line += f"    {summ}\n"
for e in report.get("escalations") or []:
    line += f"    ESCALATION [{e.get('kind','?')}] {e.get('detail','')}\n"
for c in report.get("invariant_conflicts") or []:
    line += f"    CONFLICT {c}\n"
nxt = (report.get("next_session_should_know") or "").strip()
if nxt: line += f"    NEXT: {nxt}\n"
with open(prog, "a") as f: f.write(line + "\n")

# session.json — runner statistics
try:
    with open(sess) as f: s = json.load(f)
except Exception:
    s = {}
st = s.setdefault("statistics", {})
timings = st.setdefault("iterationTimings", [])
n = st.get("totalIterations", 0) + 1
st["totalIterations"] = n
timings.append({"iteration": n, "task": idx, "status": status,
                "startTime": int(started * 1000), "endTime": int(ended * 1000),
                "durationMs": dur_ms})
if status == "completed":
    st["successfulIterations"] = st.get("successfulIterations", 0) + 1
    st["completedIterations"] = st.get("completedIterations", 0) + 1
else:
    st["failedIterations"] = st.get("failedIterations", 0) + 1
st["totalDurationMs"] = st.get("totalDurationMs", 0) + dur_ms
st["averageDurationMs"] = st["totalDurationMs"] // max(1, n)
st["successRate"] = round(st.get("successfulIterations", 0) / max(1, n), 4)
s["statistics"] = st
s["currentIteration"] = n
s["currentTaskIndex"] = idx
s["totalIterations"] = n
s["lastUpdateTime"] = int(ended * 1000)
s.setdefault("startTime", int(started * 1000))
s["elapsedTimeSeconds"] = int((ended * 1000 - s["startTime"]) / 1000)
s["status"] = "running"
with open(sess, "w") as f:
    json.dump(s, f, indent=2, sort_keys=True); f.write("\n")

# session-memory.json — what later sessions inherit
try:
    with open(mem) as f: m = json.load(f)
except Exception:
    m = {}
m.setdefault("failedApproaches", [])
m.setdefault("lessonsLearned", [])
m.setdefault("successfulPatterns", [])
m.setdefault("taskNotes", {})
for item in report.get("failed_approaches") or []:
    entry = f"task {idx:02d}: {item}"
    if entry not in m["failedApproaches"]: m["failedApproaches"].append(entry)
for item in report.get("lessons") or []:
    entry = f"task {idx:02d}: {item}"
    if entry not in m["lessonsLearned"]: m["lessonsLearned"].append(entry)
note = {"status": status, "title": task["title"]}
for k in ("summary", "makes_buildable", "next_session_should_know", "deferred"):
    if report.get(k): note[k] = report[k]
m["taskNotes"][f"{idx:02d}"] = note
m["lastUpdated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
with open(mem, "w") as f:
    json.dump(m, f, indent=2, sort_keys=True); f.write("\n")

print(status)
PY
}

# --- modes ------------------------------------------------------------------
if [ "$MODE" = "list" ]; then
  python3 - "$PRD_JSON" "$REPORTS" <<'PY'
import json, os, sys
tasks = json.load(open(sys.argv[1]))["tasks"]; reports = sys.argv[2]
for i, t in enumerate(tasks):
    st = "done" if t.get("done") else "-"
    rp = os.path.join(reports, f"task-{i:02d}.json")
    if os.path.exists(rp):
        try: st = json.load(open(rp)).get("status", st)
        except Exception: st = "bad-report"
    print(f"{i:2d}  {st:<10} {t['title']}")
PY
  exit 0
fi

if [ "$MODE" = "status" ]; then
  say "${bold}MAESTRO HELENA — implementation status${rst}"
  budget_report
  python3 - "$PRD_JSON" "$REPORTS" <<'PY'
import json, os, sys
tasks = json.load(open(sys.argv[1]))["tasks"]; reports = sys.argv[2]
done = sum(1 for t in tasks if t.get("done"))
stuck = []
for i, t in enumerate(tasks):
    rp = os.path.join(reports, f"task-{i:02d}.json")
    if not t.get("done") and os.path.exists(rp):
        try: s = json.load(open(rp)).get("status")
        except Exception: s = "bad-report"
        if s in ("failed", "blocked", "partial", "bad-report"):
            stuck.append((i, s, t["title"]))
print(f"Tasks:    {done}/{len(tasks)} done")
nxt = next((i for i, t in enumerate(tasks) if not t.get("done")), None)
if nxt is not None:
    print(f"Next:     {nxt:2d}  {tasks[nxt]['title']}")
else:
    print("Next:     — nothing left")
if stuck:
    print("Needs attention:")
    for i, s, ti in stuck:
        print(f"          {i:2d}  {s:<10} {ti}")
PY
  exit 0
fi

# --- the run loop -----------------------------------------------------------
# What the run is actually configured to do. Model and effort are blank unless
# asked for, in which case Claude Code picks; say so rather than printing "".
kv() { printf '  %s%-12s%s %s\n' "$dim" "$1" "$rst" "$2"; }

run_banner() {
  local sel perm

  if [ -n "$TASK_INDEX" ]; then
    sel="task $TASK_INDEX only"
  elif [ "$ITERATIONS" -eq 1 ]; then
    sel="the next unfinished task"
  else
    sel="up to $ITERATIONS tasks, from the next unfinished one"
  fi
  [ "$RETRY_FAILED" -eq 1 ] && sel="$sel ${dim}(failed/blocked eligible)${rst}"

  perm="$PERMISSION_MODE"
  [ -n "${IS_SANDBOX:-}" ] && perm="$perm ${dim}(IS_SANDBOX=1)${rst}"

  kv "model"    "${MODEL:-${dim}Claude Code default${rst}}"
  kv "effort"   "${EFFORT:-${dim}Claude Code default${rst}}"
  kv "cli"      "$(claude --version 2>/dev/null | head -1 || echo unknown)"
  kv "running"  "$sel"
  kv "perms"    "$perm"
  kv "timeout"  "$([ "$TIMEOUT_SECONDS" -gt 0 ] && echo "${TIMEOUT_SECONDS}s per session" || echo "${dim}none${rst}")"
  kv "budget"   "$([ "$SKIP_BUDGET" -eq 1 ] && echo "${ylw}gate skipped${rst}" || echo "stop below ${MIN_REMAINING}% remaining")"
  kv "workdir"  "$ROOT"
  [ "$DRY_RUN" -eq 1 ] && kv "mode" "${ylw}dry run — nothing will be executed${rst}"
  return 0
}

say "${bold}MAESTRO HELENA — implementation runner${rst}"
say "${dim}one task, one fresh session; the report is the handover${rst}"
say ""
run_banner
say ""

if [ -n "$TASK_INDEX" ]; then
  ntasks="$(python3 -c "import json;print(len(json.load(open('$PRD_JSON'))['tasks']))")"
  [ "$TASK_INDEX" -lt "$ntasks" ] || die "--task $TASK_INDEX out of range 0..$((ntasks - 1))"
fi

overall=0
for ((run = 1; run <= ITERATIONS; run++)); do

  if ! budget_gate; then
    [ "$run" -gt 1 ] && say "${dim}$((run - 1)) task(s) ran before the budget gate stopped the loop.${rst}"
    exit 3
  fi

  idx="$(pick_task)" || die "could not read $PRD_JSON"
  if [ -z "$idx" ]; then
    info "no unfinished tasks left."
    say  "${dim}Use --list to see them, or --task N --retry-failed to redo one.${rst}"
    [ "$run" -eq 1 ] && exit 4 || exit "$overall"
  fi

  nn="$(printf '%02d' "$idx")"
  title="$(task_field "$idx" title)"
  sid="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  log="$LOGS/task-$nn-$(date +%Y%m%d-%H%M%S).json"

  say ""
  say "${bold}── iteration $run/$ITERATIONS · task $idx ──${rst}"
  say "  $title"
  say "  ${dim}session $sid${rst}"
  say "  ${dim}report  prds/reports/task-$nn.json${rst}"

  prompt="$(build_prompt "$idx")"

  cmd=(claude -p "$prompt"
       --session-id "$sid"
       --output-format json
       --permission-mode "$PERMISSION_MODE"
       --add-dir "$ROOT")
  [ -n "$MODEL" ]  && cmd+=(--model "$MODEL")
  [ -n "$EFFORT" ] && cmd+=(--effort "$EFFORT")

  if [ "$DRY_RUN" -eq 1 ]; then
    say ""
    say "${ylw}--dry-run — would run:${rst}"
    printf '  claude -p <prompt> --session-id %s --output-format json --permission-mode %s --add-dir %s%s%s\n' \
      "$sid" "$PERMISSION_MODE" "$ROOT" \
      "${MODEL:+ --model $MODEL}" "${EFFORT:+ --effort $EFFORT}"
    say ""
    say "${ylw}prompt:${rst}"
    printf '%s\n' "$prompt" | sed 's/^/  | /'
    exit 0
  fi

  # A stale report from an earlier attempt must not be read as this one's result.
  rm -f "$REPORTS/task-$nn.json"

  started="$(date +%s.%N)"
  set +e
  if [ "$TIMEOUT_SECONDS" -gt 0 ]; then
    timeout --signal=INT "$TIMEOUT_SECONDS" "${cmd[@]}" >"$log" 2>"$log.stderr"
  else
    "${cmd[@]}" >"$log" 2>"$log.stderr"
  fi
  code=$?
  set -e
  ended="$(date +%s.%N)"

  [ "$code" -eq 124 ] && warn "session hit the --timeout of ${TIMEOUT_SECONDS}s"

  # A session that dies before it starts leaves an empty log and its only
  # explanation on stderr. Surface that instead of reporting a bare exit code.
  if [ -s "$log.stderr" ]; then
    if [ "$code" -ne 0 ] && [ ! -s "$log" ]; then
      warn "the session produced no output; stderr said:"
      sed 's/^/         /' "$log.stderr" >&2
    fi
  else
    rm -f "$log.stderr"
  fi

  if [ ! -f "$REPORTS/task-$nn.json" ]; then
    warn "the agent wrote no report — treating the task as failed"
    python3 - "$REPORTS/task-$nn.json" "$idx" "$title" "$code" <<'PY'
import json, sys
p, idx, title, code = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
json.dump({"task_index": idx, "title": title, "status": "failed",
           "summary": f"Session ended with exit code {code} and wrote no report.",
           "escalations": [], "invariant_conflicts": [], "lessons": [],
           "failed_approaches": [], "files_changed": [],
           "next_session_should_know":
               "The previous session produced no report. Check prds/logs/ before "
               "assuming nothing was changed on disk."},
          open(p, "w"), indent=2)
PY
  fi

  status="$(record_result "$idx" completed "$code" "$started" "$ended" "$sid")"

  case "$status" in
    completed) say "  ${grn}completed${rst} — prd.json marked done" ;;
    partial)   say "  ${ylw}partial${rst} — remainder is in the report" ;;
    blocked)   say "  ${ylw}blocked${rst} — needs a decision; see the report's escalations" ;;
    *)         say "  ${red}$status${rst} — see prds/reports/task-$nn.json and $log" ;;
  esac

  if [ "$status" != "completed" ]; then
    overall=2
    say ""
    warn "stopping the loop: task $idx ended '$status'."
    warn "read prds/reports/task-$nn.json, then re-run with --task $idx --retry-failed."
    exit 2
  fi
done

say ""
info "done — $ITERATIONS task(s) completed."
budget_report
exit "$overall"
