# Sigma Rules — Local Clone Architecture

## How THEORY fetches Sigma rules

THEORY uses a **local clone** of the SigmaHQ/sigma repository stored at
`.cache/sigma-repo/`. This means:

- Zero API rate limits
- Instant results after initial clone
- Works fully offline
- No GitHub token required
- Full rule coverage (no artificial caps per technique)

## First-time setup

The first time you run `--sources sigma`, THEORY automatically clones the
SigmaHQ repository:

```
ℹ  Sigma rules: cloning SigmaHQ/sigma repository (one time only).
   This takes ~1-2 minutes and uses ~150MB of disk space.
   After this, all Sigma queries run instantly with no rate limits.
   Location: .cache/sigma-repo/
```

**This only happens once.** All subsequent runs are instant — THEORY greps
the local clone with no network calls.

## Keeping rules up to date

```bash
python3 theory.py --update-bundles
```

This runs `git pull` on the Sigma repo alongside refreshing the ATT&CK bundle.
Run it periodically to stay current with new detection rules.

## Manual clone (if automatic fails)

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git .cache/sigma-repo
```

## Technical details

| Setting | Value |
|---|---|
| Repo location | `.cache/sigma-repo/` |
| Clone method | Shallow (`--depth 1`) — ~150MB |
| Query method | Local `grep` on `.yml` files |
| Query time | < 1 second per technique |
| Update method | `git pull` via `--update-bundles` |
| GitHub token | Not required |
| Rate limits | None |
