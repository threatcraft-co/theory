#!/usr/bin/env bash
# =============================================================================
# THEORY v2.0 - live demo
#
# A paced walk through what makes THEORY different from "a pile of feeds":
#
#   1  Identity     - which actor did you mean? (and refusing to guess)
#   2  Dossier      - one actor, many sources, one merged profile
#   3  Attribution  - evidence is labelled, shared tooling is not blamed
#   4  Outputs      - the same profile as STIX, Navigator, HTML, CSV...
#   5  Memory       - the correlation graph accumulates across runs
#   6  Change       - what's different since last time
#   7  Ask          - grounded Q&A (optional: needs a local model)
#   8  Guardrails   - the tests that hold the fixes in place
#
# Usage (from the repo root, with THEORY installed):
#
#   ./demo.sh                 run everything, press Enter between steps
#   ./demo.sh 1 5             run only acts 1 and 5
#   DEMO_PACE=auto ./demo.sh  advance by itself (DEMO_DELAY seconds, default 4)
#   DEMO_PACE=none ./demo.sh  no pauses (also the default when not a terminal)
#   ./demo.sh --help
#
# Safe to run on stage:
#   * Uses only keyless sources (mitre, misp_galaxy, malpedia, cisa, cisa_kev).
#   * API keys in your environment and any .env file are IGNORED, so no key can
#     appear on screen and no quota is spent. The LLM is switched off.
#   * Everything is written to ./.demo (gitignored). Your real caches, graph and
#     dossiers are never touched. Delete ./.demo to reset.
#
# Rehearse once with network access before presenting: the first run downloads
# the ATT&CK bundle and a few other public datasets into ./.demo/.cache.
# =============================================================================

set -euo pipefail
umask 077

# ── Configuration ────────────────────────────────────────────────────────────

DEMO_HOME="${DEMO_HOME:-$PWD/.demo}"
DEMO_PACE="${DEMO_PACE:-}"
DEMO_DELAY="${DEMO_DELAY:-4}"

if [ -z "$DEMO_PACE" ]; then
    if [ -t 0 ] && [ -t 1 ]; then DEMO_PACE="manual"; else DEMO_PACE="none"; fi
fi

# Isolation: all state under DEMO_HOME, nothing secret in the environment.
export THEORY_HOME="$DEMO_HOME"
export THEORY_DISABLE_DOTENV=1
export THEORY_LLM=off
for var in OTX_API_KEY NVD_API_KEY VULDB_API_KEY GITHUB_TOKEN ABUSECH_API_KEY \
           GREYNOISE_API_KEY ABUSEIPDB_API_KEY URLSCAN_API_KEY \
           ANTHROPIC_API_KEY OPENAI_API_KEY THEORY_LLM_PROVIDER THEORY_CONFIG_DIR; do
    unset "$var" || true
done

# ── Presentation helpers ─────────────────────────────────────────────────────

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RESET=""
fi

rule() { printf '%s' "${CYAN}"; printf '━%.0s' $(seq 1 74); printf '%s\n' "${RESET}"; }

act() {
    echo ""; rule
    printf '  %s%s%s\n' "${BOLD}" "$1" "${RESET}"
    rule; echo ""
}

say()  { printf '  %s\n' "$*"; }
note() { printf '  %s%s%s\n' "${DIM}" "$*" "${RESET}"; }
ok()   { printf '  %s✓%s %s\n' "${GREEN}" "${RESET}" "$*"; }
warn() { printf '  %s!%s %s\n' "${YELLOW}" "${RESET}" "$*"; }

pause() {
    case "$DEMO_PACE" in
        manual) echo ""; read -r -p "  ${DIM}⏎  continue${RESET} " _ || true; echo "" ;;
        auto)   sleep "$DEMO_DELAY" ;;
        *)      ;;
    esac
}

# Print a command the way you would type it, then run it. Arguments are passed
# through as-is (never via eval), so quoting in the demo is the quoting that runs.
run() {
    printf '\n  %s$%s %s' "${BOLD}" "${RESET}" "${GREEN}"
    printf '%q ' "$@"
    printf '%s\n\n' "${RESET}"
    "$@"
}

# Same, but the command's own output is the point, not its banner: hide stderr.
run_quiet_err() {
    printf '\n  %s$%s %s' "${BOLD}" "${RESET}" "${GREEN}"
    printf '%q ' "$@"
    printf '%s\n\n' "${RESET}"
    "$@" 2>/dev/null
}

# `--actor X --technique T` collects X first (so the graph is current) and then
# answers the connection question. On stage only the answer matters.
run_connection() {
    printf '\n  %s$%s %s' "${BOLD}" "${RESET}" "${GREEN}"
    printf '%q ' "$@"
    printf '%s\n\n' "${RESET}"
    "$@" 2>/dev/null | sed -n '/Connection query/,$p'
}

# Read a JSON profile on stdin and print selected facts. Quiet failure so a
# surprising profile cannot crash the show.
profile_summary() {
    python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception as exc:
    print("  (could not read profile: %s)" % exc); sys.exit(0)
print("  resolved to   : %s" % d.get("actor_name"))
print("  ATT&CK group  : %s" % (d.get("mitre_group_id") or d.get("mitre_id") or "n/a"))
print("  techniques    : %d" % len(d.get("techniques", [])))
mal = [m.get("name") for m in d.get("malware", []) if m.get("name")]
print("  malware       : %s" % (", ".join(mal[:5]) + (" ..." if len(mal) > 5 else "") if mal else "n/a"))
'
}

# ── Preflight ────────────────────────────────────────────────────────────────

preflight() {
    act "PREFLIGHT"

    if ! command -v theory >/dev/null 2>&1; then
        echo "  ✗ 'theory' not found. From the repo root: pip install -e ." >&2
        exit 1
    fi
    ok "theory CLI installed"

    if ! command -v python3 >/dev/null 2>&1; then
        echo "  ✗ python3 not found" >&2; exit 1
    fi
    ok "python3 available"

    mkdir -p "$DEMO_HOME/.cache" "$DEMO_HOME/work"

    # Fresh graph and dossiers every run, so "memory" starts empty on stage.
    rm -rf "$DEMO_HOME/output"
    ok "demo workspace: $DEMO_HOME (graph starts empty)"

    # Datasets: reuse the repo's own cache if present (works offline),
    # otherwise download once.
    if [ ! -f "$DEMO_HOME/.cache/enterprise-attack.json" ]; then
        if [ -f ".cache/enterprise-attack.json" ]; then
            cp -R .cache/. "$DEMO_HOME/.cache/"
            ok "reused ./.cache datasets (no download needed)"
        else
            warn "datasets missing - downloading once into $DEMO_HOME/.cache"
            theory --update-bundles
        fi
    else
        ok "datasets cached"
    fi

    if [ ! -f "$DEMO_HOME/.cache/enterprise-attack.json" ]; then
        echo "  ✗ ATT&CK bundle still missing; run once with network access." >&2
        exit 1
    fi

    ok "API keys and .env ignored; LLM off; keyless sources only"
}

# ── Act 1: identity ──────────────────────────────────────────────────────────

act1() {
    act "1  IDENTITY - which actor did you mean?"
    say "Threat actors have a dozen names. Three vendors, one group:"
    pause

    for name in "Fancy Bear" "Forest Blizzard" "APT28"; do
        printf '\n  %s$%s %stheory --actor "%s" --sources mitre%s\n' "${BOLD}" "${RESET}" "${GREEN}" "$name" "${RESET}"
        theory --actor "$name" --sources mitre --output json --no-save --no-graph 2>/dev/null | profile_summary
    done
    echo ""
    pause

    say "Aliases used to be matched loosely. Lazarus Group came back as APT38,"
    say "APT41 as APT17. Now names resolve by exact match, pinned to ATT&CK ids:"
    printf '\n  %s$%s %stheory --actor "Lazarus Group" --sources mitre%s\n' "${BOLD}" "${RESET}" "${GREEN}" "${RESET}"
    theory --actor "Lazarus Group" --sources mitre --output json --no-save --no-graph 2>/dev/null | profile_summary
    echo ""
    pause

    say "And when it does not know, it says so instead of guessing:"
    printf '\n  %s$%s %stheory --actor a%s\n\n' "${BOLD}" "${RESET}" "${GREEN}" "${RESET}"
    set +e
    theory --actor a --sources mitre --no-save --no-graph 2>&1 | tail -n 8
    status=${PIPESTATUS[0]}
    set -e
    echo ""
    note "exit code: $status  (a confident dossier about 'a' would be worse than none)"
}

# ── Act 2: the dossier ───────────────────────────────────────────────────────

act2() {
    act "2  DOSSIER - one actor, many sources, one profile"
    say "Default sources need no key: ATT&CK, MISP Galaxy, Malpedia, CISA, CISA KEV."
    pause
    run theory --actor APT28
    echo ""
    note "Saved as markdown, and recorded in the graph for act 5."
}

# ── Act 3: attribution ───────────────────────────────────────────────────────

act3() {
    act "3  ATTRIBUTION - evidence is labelled, not assumed"
    say "Every indicator carries how strongly it belongs to the actor:"
    echo ""
    say "  ${BOLD}actor${RESET}        a source explicitly attributes it (advisory, adversary tag)"
    say "  ${BOLD}family${RESET}       tied to a malware family the actor uses"
    say "  ${BOLD}shared_tool${RESET}  tied to software hundreds of unrelated groups use"
    pause

    say "That last one matters. A Cobalt Strike C2 server is not 'APT28 infrastructure'"
    say "just because APT28 also uses Cobalt Strike. THEORY skips shared tooling by"
    say "default; ${BOLD}--include-shared-tooling${RESET} opts back in, and the label travels"
    say "into STIX, the CSV and the graph so you can filter before building a blocklist."
    echo ""
    python3 -I - <<'PY'
import yaml
from theory.paths import config_file
d = yaml.safe_load(config_file("shared_tooling.yaml").read_text(encoding="utf-8"))
names = d.get("shared_tooling", [])
print("  %d tools are treated as shared by default, for example:" % len(names))
print("    " + ", ".join(names[:8]) + ", ...")
PY
}

# ── Act 4: outputs ───────────────────────────────────────────────────────────

act4() {
    act "4  OUTPUTS - one profile, every format your tools expect"
    say "STIX 2.1 for MISP/OpenCTI/Sentinel, an ATT&CK Navigator layer, a shareable"
    say "HTML report, an IOC CSV, an IR playbook, Sigma skeletons for detection gaps."
    pause
    run_quiet_err theory --actor APT28 --sources mitre,misp_galaxy --output all --no-graph >/dev/null || true
    echo ""
    say "Files written for APT28:"
    echo ""
    find "$DEMO_HOME/output" -type f -iname '*apt28*' ! -name '*.previous.json' 2>/dev/null \
        | sort | while read -r f; do
            printf '    %-52s %s\n' "${f#"$DEMO_HOME"/}" "$(wc -c <"$f" | tr -d ' ') bytes"
        done
    echo ""
    python3 -I - "$DEMO_HOME/output" <<'PY'
import json, sys
from collections import Counter
from pathlib import Path
root = Path(sys.argv[1])
for p in sorted(root.rglob("*apt28*.json")):
    if p.name.endswith(".previous.json"):
        continue
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        continue
    if isinstance(d, dict) and d.get("type") == "bundle":
        c = Counter(o.get("type") for o in d.get("objects", []))
        print("  STIX bundle   : %d objects (%s)" % (
            sum(c.values()), ", ".join("%s %d" % kv for kv in c.most_common(4))))
    elif isinstance(d, dict) and "techniques" in d and "domain" in d:
        print("  Navigator     : %d techniques coloured by confidence" % len(d["techniques"]))
PY
    echo ""
    note "Open the .html file in a browser; the .json layer imports into ATT&CK Navigator."
}

# ── Act 5: memory ────────────────────────────────────────────────────────────

act5() {
    act "5  MEMORY - the graph accumulates across runs"
    say "Every run feeds a local correlation graph. A second actor goes in:"
    pause
    run_quiet_err theory --actor APT29 --sources mitre,cisa_kev >/dev/null || true
    ok "APT29 recorded. The graph now holds both actors."
    pause

    # Pick techniques from the two real profiles rather than hard-coding ids.
    local a b picks shared only28
    a="$DEMO_HOME/work/apt28.json"; b="$DEMO_HOME/work/apt29.json"
    theory --actor APT28 --sources mitre --output json --no-save --no-graph 2>/dev/null >"$a" || true
    theory --actor APT29 --sources mitre --output json --no-save --no-graph 2>/dev/null >"$b" || true
    picks="$(python3 -I - "$a" "$b" <<'PY'
import json, sys
def ids(path):
    try:
        return [t["technique_id"] for t in json.load(open(path))["techniques"]]
    except Exception:
        return []
a, b = ids(sys.argv[1]), ids(sys.argv[2])
shared = next((t for t in a if t in set(b)), "")
only = next((t for t in a if t not in set(b)), "")
print(shared, only)
PY
)"
    shared="${picks%% *}"; only28="${picks##* }"

    if [ -n "$shared" ]; then
        say "Which actors use ${BOLD}${shared}${RESET}? No new collection - straight from the graph:"
        run theory --technique "$shared"
        pause
        say "Is APT28 connected to it? A direct link, or a shared bridge node:"
        run_connection theory --actor APT28 --technique "$shared" --sources mitre --no-save
    fi
    if [ -n "$only28" ] && [ "$only28" != "$shared" ]; then
        pause
        say "And the honest negative. APT29 and ${BOLD}${only28}${RESET}:"
        run_connection theory --actor APT29 --technique "$only28" --sources mitre --no-save
    fi
}

# ── Act 6: change tracking ───────────────────────────────────────────────────

act6() {
    act "6  CHANGE - what is different since last time"
    say "THEORY keeps a step of history so you can ask what moved. To show it without"
    say "waiting a week, we simulate 'yesterday' by removing a technique from a copy:"
    pause

    local new old
    new="$DEMO_HOME/work/apt28_today.json"; old="$DEMO_HOME/work/apt28_yesterday.json"
    theory --actor APT28 --sources mitre --output json --no-save --no-graph 2>/dev/null >"$new" || true
    python3 -I - "$new" "$old" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    if d.get("techniques"):
        d["techniques"] = d["techniques"][1:]       # "yesterday" lacked one
    json.dump(d, open(sys.argv[2], "w"))
except Exception as exc:
    print("  (could not build the comparison file: %s)" % exc)
PY
    if [ -s "$old" ]; then
        run theory diff --from "$old" --to "$new"
    fi
    echo ""
    note "Real use: run it twice, then 'theory diff --actor APT28', or 'theory --actor APT28 --watch'."
}

# ── Act 7: grounded Q&A (optional) ───────────────────────────────────────────

act7() {
    act "7  ASK - answers only from what THEORY has recorded"
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
        say "A local model (Ollama) is running, so nothing leaves this machine."
        pause
        THEORY_LLM=local run theory ask "Which techniques do APT28 and APT29 have in common?" || \
            warn "ask did not complete; skipping"
    else
        warn "Skipped: this act needs a local model (Ollama on localhost:11434)."
        note "Answers come only from the graph and your notes, never from model memory."
    fi
}

# ── Act 8: guardrails ────────────────────────────────────────────────────────

act8() {
    act "8  GUARDRAILS - the tests that keep it honest"
    if ! python3 -c 'import pytest' >/dev/null 2>&1 || [ ! -d tests ]; then
        warn "Skipped: needs a repo checkout with the dev extras (pip install -e '.[dev]')."
        return 0
    fi
    say "Sixty golden cases check actor resolution against ATT&CK's own alias lists,"
    say "so a future data import cannot quietly merge two groups again:"
    pause
    run python3 -m pytest tests/test_actor_identity.py -q -p no:cacheprovider
    pause
    say "And the rule that a failed lookup is never remembered as 'no data' - timeout,"
    say "rate limit, bad key - for ThreatFox, URLhaus and MalwareBazaar alike:"
    run python3 -m pytest tests/test_abusech_failure_modes.py -q -p no:cacheprovider
}

# ── Main ─────────────────────────────────────────────────────────────────────

usage() {
    sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
}

closing() {
    act "SUMMARY"
    ok "Names resolve exactly, or THEORY says it does not know"
    ok "Twenty sources, thirteen with no key, merged into one profile"
    ok "Every indicator labelled actor / family / shared_tool"
    ok "One profile, many formats; a graph that remembers; a diff that shows change"
    ok "Failed lookups are never mistaken for 'nothing found'"
    echo ""
    say "github.com/threatcraft-co/theory"
    note "Demo data lives in $DEMO_HOME - delete it to reset."
    echo ""
}

main() {
    case "${1:-}" in
        -h|--help|help) usage; exit 0 ;;
    esac

    local -a selected=()
    if [ "$#" -gt 0 ]; then
        for n in "$@"; do
            case "$n" in
                [1-8]) selected+=("$n") ;;
                *) echo "unknown act '$n' (expected 1-8)" >&2; exit 2 ;;
            esac
        done
    else
        selected=(1 2 3 4 5 6 7 8)
    fi

    preflight
    pause
    for n in "${selected[@]}"; do
        "act$n"
        pause
    done
    closing
}

main "$@"
