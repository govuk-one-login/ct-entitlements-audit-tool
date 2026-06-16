# Rule: Mandatory Conversation Markdown Block Append

## Purpose

Ensure that every response generated includes a full record of the conversation in a standardized Markdown
syntax block, allowing the user to quickly maintain an offline query log.

## Instructions

- At the very end of EVERY response you generate, you MUST append this markdown code block to file .agent-log.md in repo
root directory, create file if needed. The block must contant these elements:
- A horizontal rule divider (`---`)
- Todays date and time
- The exact text of the user's latest prompt
- The exact text of your latest response

## Example

```markdown
---
project: "[Insert Project Workspace Name]"
date: "[time of query, in ISO 8601 format]"
language: "[Insert primary programming language or 'General'/'DevOps']"
files_affected:
  - "[Insert active file path, or 'None']"
tags: ["ai-assisted", "[Insert relevant technology tag, e.g., 'docker', 'react', 'regex']"]
rules: ["ai-assisted", "[Insert relevant technology tag, e.g., 'docker', 'react', 'regex']"]
### User Prompt:
[Insert prompt here]

### Assistant Response:
[Insert full text of your response, including any code examples, tables any anything else you write in the chat here]
```
