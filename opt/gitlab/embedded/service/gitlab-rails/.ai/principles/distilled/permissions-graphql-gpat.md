---
source_checksum: 845e2a2f616941ed
distilled_at_sha: b0b7e1628f9fb689a18cee2ec91c621c6a26dd2d
---
<!-- Auto-generated from docs.gitlab.com by gitlab-ai-principles-distiller — do not edit manually -->

> **Prerequisite:** If you haven't already, also read .ai/principles/distilled/permissions-fundamentals.md - it contains foundational rules that apply to all permissions work.

# Permissions: GraphQL Granular PAT Principles

## Checklist

### Permission Definition Files

- Use `bin/permission <permission_name>` to generate raw permission definition files; pass `-a` (action) and `-r` (resource) flags to override the default name-splitting behavior when the action is more than one word.
- Place raw permission definition files at exactly `config/authz/permissions/<resource>/<action>.yml`; DO NOT add extra directories between the base path and the final filename.
- Ensure each permission definition file includes a `name` and `description` field; the `description` must follow the pattern `"Grants the ability to <action> <resource>"`.
- Include a `conditionally_enables` field for private (underscore-prefixed) permissions, set to the broader permission(s) that imply it, or `null` when none apply.
- Ensure each resource directory has a `.metadata.yml` with a valid `feature_category` entry from `config/feature_categories.yml`; look at existing API endpoints for that resource to find the correct category.
- Run `bundle exec rake gitlab:permissions:validate` (or rely on the Lefthook pre-push hook) to validate all permission definition files before pushing.

### Permission Naming

- Name permissions based on what the type **represents** or what the mutation **does**, not the GraphQL schema structure (e.g., `IssueType` → `read_issue`, `Mutations::Issues::Create` → `create_issue`).
- Use `read_<resource>` for object types, `create_<resource>` for create mutations, `update_<resource>` for update mutations, and `delete_<resource>` for delete mutations; use a specific permission name for special-action mutations (move, archive, transfer, etc.).
- Follow the Naming Permissions and Disallowed Actions conventions (see `.ai/principles/distilled/permissions-fundamentals.md` § Permission Naming Conventions) enforced by the validation Rake task.

### Assignable Permissions

- Create assignable permission YAML files manually at `config/authz/permission_groups/assignable_permissions/<category>/<resource>/<action>.yml`; DO NOT place them at any other path.
- Prefer adding raw permissions to an existing assignable permission over creating a new one; create a new assignable permission only when the raw permissions represent a capability users should be able to grant separately from existing ones for that resource.
- Decide the granularity of an assignable permission before tokens or roles hold it, because splitting or merging later changes what existing tokens and roles can do; when the factors conflict, explain the choice in the merge request.
- Favor a new assignable permission when the action needs more than read access to the parent (higher role, license, add-on), exposes sensitive data (secrets, tokens, keys) or data from other projects or groups, has its own endpoints and lifecycle, has more impact than the existing grant, or needs different `assignable_when` conditions at the same boundary.
- Favor an existing assignable permission when the raw permission covers a nested resource reached only through the parent, reverses an action already granted, performs the same action on another format or source, changes the state of the parent, or covers metadata anyone who can read the parent already sees.
- Keep read, create, update, and delete actions on a resource in separate assignable permissions by default; check related assignable permissions for the resource and stay consistent with them.
- Use one assignable permission for a response whose fields are protected by different user permissions; the user permission checks decide which fields are included.
- Create the assignable permission in the merge request that adds the first check for its raw permissions; usually omit an assignable permission for a private (`_`-prefixed) raw permission or one that only hides or shows fields inside an endpoint or type another assignable permission already grants.
- Ensure every raw permission listed in an assignable permission's `permissions` array already exists as a raw permission definition file before referencing it.
- Set the `available_for` field to `granular_access_token`, `role`, or both; an assignable permission that declares `granular_access_token` must have at least one of its raw permissions referenced by a REST authorization decorator or GraphQL granular scope directive.
- Set the `boundaries` field to only the organizational levels (`project`, `group`, `user`, `instance`) where the bundled raw permissions actually apply; use the principle of least privilege and DO NOT include boundaries that the endpoints do not support.
- Use `instance` boundary sparingly — typically only for admin-facing permissions.
- Add a category `.metadata.yml` only when titleization produces an incorrect display name (e.g., `ci_cd` → `"CI/CD"`); DO NOT create one when the folder name titleizes correctly.
- Add a resource `.metadata.yml` only when the resource name contains an acronym, brand name, or unconventional action that titleizes or pluralizes incorrectly, or when the generated description needs a custom noun.
- Include `<actions>` interpolation in any custom `description` field in a resource `.metadata.yml` so the action list stays in sync automatically.
- Ensure the `boundaries` field on an assignable permission covers the union of all `boundary_type` values declared by its raw permissions' endpoints and directives; the Lefthook pre-push validation catches mismatches.
- Use the optional `assignable_when` field to declare conditions a user must meet for the permission to be offered in the token creation UI (available conditions: `admin`, `gitlab_team_member`, `saas`, `self_managed`); every boundary listed in `assignable_when` must also appear in the permission's `boundaries` field. Note: `assignable_when` is NOT a security control — endpoints must still enforce the same conditions at request time.

### Assignable Permission Lifecycle

- DO NOT remove an assignable permission unless the underlying API functionality is also being removed; removal is a breaking change that causes tokens with that permission to silently lose access.
- DO NOT rename an assignable permission without a three-step migration: (1) add the new YAML file, queue a `rename_granular_scope_permission` batched background migration, and mark the old permission as `deprecated: true`; (2) finalize the batched background migration in a later milestone; (3) remove the deprecated file using `bundle exec rake gitlab:permissions:assignable:cleanup_deprecated`.
- DO NOT add raw permissions to an existing assignable permission except when adding support for new API endpoints; doing so immediately grants increased access to all existing tokens with that assignable permission.
- DO NOT remove raw permissions from an assignable permission without a migration strategy; removal immediately revokes access for all tokens holding that assignable permission.
- Prefer changing `boundary_type` between `project` and `group` (safe, because projects belong to groups); treat any change to or from `user` or `instance` as a breaking change requiring token holders to recreate their scopes.
- DO NOT rename a raw permission without updating both its definition file and every assignable permission YAML that references it; no database migration is required for raw permission renames.

### GraphQL Authorization Directives

- Add `authorize_granular_token` to every GraphQL object type and mutation that exposes protected resources; the `gitlab:permissions:validate` Rake task requires every object type to declare either a directive or a `skip_reason:`, unless grandfathered in `config/authz/graphql/authorization_todo.txt` (DO NOT add new entries to that file).
- Use `boundary: :project` (or `:group`, `:user`, `:instance`) on object types where the resolved object has a method to reach the boundary (e.g., `issue.project`); use `boundary_argument: :project_path` on mutations and root query fields where the boundary is passed as an argument.
- Declare the directive on the resolver for root query fields, using `boundary_argument` to read the boundary from the field arguments (directives declared on a resolver apply to the fields that mount it); the field resolves to `null` when the token lacks the permission.
- Use `boundary: :itself` when the type itself is the boundary object (e.g., `ProjectType` or `GroupType`).
- Use `boundary: :user` or `boundary: :instance` for standalone resources that do not belong to a specific project or group.
- When a mutation's `boundary_argument` resolves to a record that is not itself a Project or Group, combine `boundary_argument` with `boundary` so the extractor locates the record and then calls `boundary` on it to reach the Project or Group.
- Use `boundaries:` (array of hashes, each with `boundary_type` and optionally `boundary` or `boundary_argument`) when a resource can belong to different boundary types; a concrete boundary (project or group) takes precedence over a standalone boundary (`user` or `instance`), and a directive whose resolved object does not match its declared `boundary_type` is skipped.
- Ensure `permissions` references only valid permission symbols from `Authz::PermissionGroups::Assignable.all_permissions`; the `gitlab:permissions:validate` Rake task enforces this.
- Ensure `boundary_type` matches at least one boundary declared in the corresponding assignable permission's `boundaries` field; the Lefthook pre-push validation catches mismatches.
- When a type with its own directive returns a type that relies on parent authorization, declare `parent_authorizes: :<permission>` on the returned type instead of bare `skip_reason: :parent_authorizes`; DO NOT rely on a legacy todo-file exemption for a new type.
- DO NOT declare `permissions:` alongside `skip_reason:`; use `skip_reason:` alone on types that intentionally opt out of granular-token authorization.
- Declare `parent_authorizes: :<permission>` on a type that relies on its parent for authorization to name the permission its data needs; the type still skips its own check, and every field that returns the type checks the declared permission before the resolver runs (on the parent's boundary for a type with its own directive, or through the field's own directive).
- Add the `parent_authorizes:` permission to the parent's assignable permission when anyone who can read the parent already sees the type's data; otherwise give it its own assignable permission and add a `rename_granular_scope_permission` migration that adds the new assignable permission to tokens holding the parent's.
- Satisfy the `gitlab:permissions:validate` checks for `parent_authorizes:`: a field with its own directive must include the declared permission; root `Query`/`Subscription` fields and mutations whose payload returns the type need their own directive; the permission must belong to an assignable permission for each boundary type of the parent and be an ability of the project or group policy; a non-null field must not return a type whose permission is outside the parent's assignable permissions; a field without its own directive that returns an interface or union needs all possible types to declare the same permission.
- DO NOT add new `parent_authorizes:` entries to `config/authz/graphql/authorization_todo.txt`.
- Ensure every path to a field on another skipped type checks the declared permission further up the path, or starts from a mutation with its own granular token check. Give a field returning an interface or union its own directive when the possible types declare different permissions.
- Tag a type, mutation, or resolver with `assignable_when:` on the `authorize_granular_token` call when it restricts access beyond membership (e.g., to administrators); the tag applies to every directive the call emits (primary boundary and every `boundaries:` entry). Individual hashes inside `boundaries:` can also set their own `assignable_when` to add conditions for that boundary only. The tag is NOT a security control — the type or mutation must still enforce the restriction itself. The validation task rejects unknown condition names and checks tags against the assignable permission YAML's `assignable_when` conditions.

### Traversal Between Authorized Types

- Understand that when a field on an authorized type returns another type that also declares `authorize_granular_token`, both directives are enforced independently; plan permissions assuming the token needs both the owner type's and the child type's permissions (the automatic traversal skip was previously implemented but is pending reimplementation — DO NOT rely on it).

### Authorization Caching and Performance

- Rely on the per-request authorization cache: multiple fields that resolve to the same boundary and permissions reuse the cached result, so the authorization service runs only once for them.
- Understand that `BoundaryExtractors::Preloader` batch-loads boundary associations across all nodes in a collection before authorization runs, avoiding N+1 queries (e.g., `issue.project` for each resolved issue); the loaded records are cached in `Gitlab::SafeRequestStore` and reused by the boundary extractors.
- Understand that legacy (non-granular) PATs skip granular authorization entirely; granular authorization only runs when the token is granular. Exception: when a boundary's root namespace has `granular_tokens_enforced?` enabled, legacy tokens are held to the same permission checks as granular tokens.

### Feature Flag

- Ensure the `granular_personal_access_tokens` feature flag is enabled for the token's user during development and testing; when the flag is disabled, granular PATs do not work for GraphQL requests.

### Documentation and Validation

- Run `bundle exec rake gitlab:permissions:graphql:compile_docs` to regenerate the fine-grained token reference documentation at `doc/auth/tokens/fine_grained_access_tokens_graphql.md`; DO NOT edit that file by hand.
- Ensure the `gitlab:permissions:validate` Rake task passes before pushing (it also runs as a Lefthook pre-push hook); it fails when the generated reference documentation is out of date, a directive's permission is not part of any assignable permission, a `skip_reason:` is undefined, a type skipped with `parent_authorizes` declares no permission or a field returning a `parent_authorizes:` type does not check the declared permission, or a directive's `assignable_when` conditions do not match the assignable permission YAML.

### Authorization Tests

- Use the `'authorizing granular token permissions for GraphQL'` shared example for both query and mutation specs; provide `user`, `boundary_object`, and `request` let-bindings.
- Use the `'authorizing granular token permissions for GraphQL with a skipped child type'` shared example to verify that a skipped child's data is returned only when its parent is authorized; provide `user`, `boundary_object`, `request`, and `skipped_data_path` let-bindings.
- Set `boundary_object` to match the `boundary_type`: `project` for `:project`, `group` for `:group`, `:user` for `:user`, `:instance` for `:instance`.
- Ensure the `user` has access to the `boundary_object` namespace (project or group) when the boundary type is `:project` or `:group`; authorization is denied otherwise.
- Verify that the shared example covers: legacy PATs still grant access, legacy tokens are denied when the boundary's top-level group enforces fine-grained tokens, granular PATs with the required permission grant access, granular PATs without the required permission are denied (unauthorized queries return `null` data with a `200` response; unauthorized mutations return a top-level GraphQL error), and the `granular_personal_access_tokens` feature flag is enforced.

## Authoritative sources

For the full picture, see:

- doc/development/permissions/granular_access/_index.md
- doc/development/permissions/granular_access/graphql_implementation_guide.md
- doc/development/permissions/granular_access/graphql_architecture.md
- doc/development/permissions/granular_access/permission_definitions.md
- doc/development/permissions/granular_access/assignable_permissions.md

