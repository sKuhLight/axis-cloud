---
description: Plan a feature or change for axis-cloud (Supabase backend) without editing code — scope, migrations, functions, security, verification, and the mandatory Plane task-tracking step. Presents a plan and waits for approval.
---

Plan the following feature or change WITHOUT editing any code or files. Produce a
written plan only; make no edits until it is explicitly approved.

Feature request: $ARGUMENTS

Work through these steps and present the result:

1. **Task tracking (MANDATORY — see CLAUDE.md / CLAUDE.local.md, "Task tracking").**
   FIRST, search this repo's Plane project (the AXISCLOUD project — coordinates live in
   `CLAUDE.local.md`) for an existing work item covering this change
   (`search_work_items` / `list_work_items`). If none exists, create one with an
   imperative title and a description of goal + why + acceptance criteria. State which
   item this maps to (existing id or "to be created"); it moves to **In Progress** when
   implementation begins.

2. **Goal & acceptance criteria.** Restate the goal in one or two sentences and list
   concrete, testable acceptance criteria.

3. **Layer placement.** Identify what the change touches — schema (a NEW migration),
   RLS/policies, a SECURITY DEFINER function/trigger, a Storage bucket/policy, an edge
   function, or `config.toml`. Remember the stack layering: protocol facts belong in
   forgefx-midi, device logic in ForgeFX, UI in Axis — only cloud persistence, sync, and
   auth belong here. If it does not belong here, say so and stop.

4. **Files to touch.** List the exact files. For any schema change, specify a NEW
   timestamped migration under `supabase/migrations/` — NEVER an edit to an existing
   applied migration. Note that any new table needs RLS + at least one policy, and any
   new bucket needs object policies.

5. **Security review points.** Call out the authz model (which key/role, JWT handling),
   whether a function must be `security definer` (and its `search_path` + EXECUTE
   grants), input validation + size caps, and that no secret is exposed.

6. **Verification plan.** State honestly how this will be verified — there is NO
   automated test gate in this repo. Typically: `npx --yes supabase@latest db reset`
   against the local stack (needs Docker) plus manual exercise of the SQL/functions
   (`functions serve <name>`). Do not assert a passing gate that does not exist.

Finally: present the full plan, then WAIT for approval. Do not make any edits.
