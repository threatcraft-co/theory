# Scheduled Bundle Updates

THEORY's local data sources (ATT&CK bundle, Sigma rules, APT campaign collection)
need periodic refreshing to stay current. Run `--update-bundles` manually anytime,
or automate it with cron (Linux/macOS) or launchd (macOS).

## What `--update-bundles` does

```
✓ Downloads latest MITRE ATT&CK STIX bundle
✓ Runs git pull on the local SigmaHQ/sigma clone
✓ Runs git pull on the CyberMonitor APT campaign collection
✓ Preserves Malpedia, OTX, and ThreatFox caches (TTL-managed)
```

## macOS — launchd (recommended)

Create a plist file at `~/Library/LaunchAgents/co.threatcraft.theory.update.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>co.threatcraft.theory.update</string>

    <key>ProgramArguments</key>
    <array>
        <string>/path/to/your/venv/bin/theory</string>
        <string>--update-bundles</string>
    </array>

    <key>WorkingDirectory</key>
    <string>/path/to/theory</string>

    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>1</integer>
        <key>Hour</key>
        <integer>6</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>

    <key>StandardOutPath</key>
    <string>/tmp/theory-update.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/theory-update.log</string>

    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
```

Replace `/path/to/your/venv` and `/path/to/theory` with your actual paths:

```bash
# Find your venv theory path
which theory

# Find your theory directory
pwd  # run from inside the theory folder
```

Then load it:

```bash
launchctl load ~/Library/LaunchAgents/co.threatcraft.theory.update.plist

# Verify it loaded
launchctl list | grep threatcraft

# Run it immediately to test
launchctl start co.threatcraft.theory.update

# Check the log
tail -f /tmp/theory-update.log

# To unload/disable
launchctl unload ~/Library/LaunchAgents/co.threatcraft.theory.update.plist
```

This runs every Monday at 6:00 AM. Adjust `Weekday` (0=Sunday, 1=Monday…6=Saturday)
and `Hour` to your preference.

## Linux — cron

```bash
# Open your crontab
crontab -e

# Add this line (runs every Monday at 6:00 AM)
0 6 * * 1 cd /path/to/theory && /path/to/venv/bin/theory --update-bundles >> /tmp/theory-update.log 2>&1
```

## How often should I update?

| Source | Recommended frequency | Notes |
|---|---|---|
| ATT&CK bundle | Monthly | MITRE releases ~4x/year |
| Sigma rules | Weekly | SigmaHQ community is very active |
| APT campaigns | Monthly | CyberMonitor collection is archival |

Weekly (every Monday) is a good default that covers all three without being excessive.
