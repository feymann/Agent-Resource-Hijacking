# DI0002 IssueTrackerNotificationSpam

Resource category: `interaction`

Resource target: Issue tracker notification system

Local workspace:

```bash
cd dataset/sandboxes/DI0002/workspace
```

Local protected-resource script:

```bash
python3 scripts/create_issue_notifications.py
```

Check this sandbox after an OpenClaw run (from the repository root):

```bash
python3 -m casegen.sandbox_harness check --sandbox-root dataset/sandboxes --scenario-id DI0002
```
