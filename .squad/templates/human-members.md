# Human Members

Reference for adding human team members to the Squad roster.

## Triggers

The coordinator enters the human-member flow when:

- User says **"add {name} as {role}"** or **"add a human for {domain}"**
- User says **"make {name} a reviewer"**
- Routing detects a human member as the target for work

## Comparison: AI Agent vs. Human Member

| | AI Agent | Human Member |
|---|----------|-------------|
| Badge | Role-specific emoji | 👤 Human |
| Charter | ✅ | ❌ |
| History | ✅ | ❌ |
| Spawned as sub-agent | ✅ | ❌ |
| Can review work | ✅ | ✅ |
| Casting (fictional name) | ✅ | ❌ (real name) |

## Adding a Human Member

Follow these steps:

1. **Use real name** — no casting. Badge: 👤 Human.
2. **Add to team.md roster:**
   ```markdown
   | {Name} | {Role} | — | 👤 Human |
   ```
3. **Add routing entries to routing.md:**
   ```markdown
   | {domain} | {Name} 👤 | {example tasks} |
   ```
4. **Do not create** `charter.md` or `history.md` for humans.
5. **Do not add** to casting registry.

## Routing to a Human

When work routes to a human member, the coordinator pauses. It never does that work itself or hands it to an AI member.

**Sign-off gates.** When `team.md`, `routing.md` or a decision says a human must approve or sign off on a kind of work (a release, version bump, tag, publish, merge or deploy), a request to do that work is not the sign-off. Before any gated step the coordinator names the rule and the human, asks whether the user is that human or has their explicit sign-off, proceeds only on an explicit yes, and records it in the decisions inbox. In a non-interactive run it stops at the gate and reports what is waiting and for whom.


1. **Present the work to the user:**
   ```
   "{Name} needs to review this. [Context about what needs review]"
   ```
2. **Non-dependent work continues immediately** — other agents proceed with unrelated tasks.
3. **Stale reminder** after >1 turn without response:
   ```
   "📌 Still waiting on {Name} for {thing}."
   ```

## Reviewing as a Human

- Humans can serve as reviewers in the review process.
- **Rejection lockout applies normally** — original author is locked out when reviewer rejects.
- User relays the human's verdict to the coordinator ("approved" or "rejected with changes").

## Decision Framework: When to Add a Human Member

| Scenario | Add to roster? | Why |
|----------|---------------|-----|
| Approves architecture decisions before implementation | ✅ Yes | Decision gate — team routes and waits |
| Reviews all docs PRs as standing reviewer | ✅ Yes | Recurring review gate |
| Occasionally reviews PRs when tagged | ❌ No | Use @mention on the PR |
| Files issues and contributes code | ❌ No | Normal GitHub collaboration |
| Makes final ship/no-ship call | ✅ Yes | Approval gate |

**Litmus test:** If you want agents to *stop and wait* for someone's input before proceeding on a specific type of work, add them. If they review asynchronously via GitHub, don't bother.

**Who is driving:** `git config user.name` tells the team who is probably at the keyboard. It is a hint, not a sign-off: for a gated step the coordinator still asks. Adding yourself to the roster is optional; it formalizes routing and tracking.

## Removing a Human

Same as removing any member:

1. Move entry to alumni section in team.md.
2. Remove from active roster.
3. Update routing.md to remove all routing entries.
