# Runtime Manifest

The current release includes a runtime-manifest layer plus a finer permission schema that drive guarded runtime refinement without executing untrusted content.

## Supported inputs

- JSON
- YAML
- partial manifests
- unknown extra fields are tolerated
- backward-compatible manifests that only provide the older `permission_surface`

## Current modeled fields

- `execution_environment`
  - `host`
  - `sandbox`
  - `mixed`
  - `unknown`
- `permission_surface`
  - `network`
  - `writable_scope`
  - `mounted_directories`
  - `mounted_secrets_or_configs`
  - `exec_allowed`
  - `process_allowed`
  - `browser_available`
  - `web_fetch_available`
  - `web_search_available`
  - `gateway_available`
  - `nodes_available`
  - `cron_available`
  - `root_admin_hint`
  - `user_identity_hint`
  - `home_directory_access`
- `permission_schema`
  - `schema_version`
  - `capability_surface`
    - `exec_allowed`
    - `process_allowed`
    - `shell_allowed`
    - `child_process_allowed`
    - `write_allowed`
    - `edit_allowed`
    - `apply_patch_allowed`
    - `direct_network`
    - `browser_network`
    - `web_fetch`
    - `gateway`
    - `nodes`
    - `cron`
    - `env_available`
    - `config_available`
    - `auth_profiles_available`
    - `local_secret_paths_available`
    - `browser_store_proximity`
  - `environment_scope`
    - `workspace_only`
    - `home_access`
    - `mounted_paths`
    - `mounted_secrets`
    - `writable_scope`
    - `read_only_scope`
  - `privilege_hint`
    - `root_admin`
    - `standard_user`
    - `sandbox_restricted`
    - `unknown`
- secret/config surfaces
  - `present_env_vars`
  - `present_config_files`
  - `auth_profiles_present`
  - `credential_store_proximity`
- `notes`

## Safe local checks

When the user does not provide every fact, the verifier may still perform guarded local checks for:

- expected env var presence
- expected config file presence
- local home-directory presence
- observed target root

These checks only confirm presence or scope. They do not read secret contents or execute skill logic.

## Why the schema is version-tolerant

The runtime schema is intentionally more abstract than any single OpenClaw build artifact. It models durable capability families and scope families instead of binding the verifier to one exact app version or one exact manifest shape.
