## Agent Logging Rule

Rules:

- At the END of every interaction, append a JSON entry to `.agent-log.json` at the repository root
- The file must remain valid JSON (a top-level array). Read the existing array, append the new entry, and write back the complete array.
- Always log, even if the prompt was a simple question with no file changes (use empty arrays/null for unused fields).
- If an action was denied (e.g. refused to write malicious code), log it with `"status": "denied"`.
- Keep the log file valid JSON at all times. Create if log file does not exist already, otherwise append.

Each entry must contain:

```json
{
  "time": "<time of prompting, in ISO 8601 timestamp>",
  "user": "<user identity, default: jan-thomas.moldung>",
  "prompt": "<the user's prompt text, summarized if very long>",
  "context": {
    "active_file": "<relative path of active file or null>",
    "pinned": "<pinned context files or null>"
    "rules": "<path to any agent rule or steering files used>"
  },
  "files_changed": ["<list of files created or modified, relative paths>"],
  "actions": [
    { "action": "<description>", "status": "taken|denied"}
  ],
  "plan": "<describe your reasoning and your plan to resolve the prompt",
  "tasks": [
    { "task":  "<describe in detail the task, the reasoning and your thinking on resolve the prompt"},
  ]
}
```
