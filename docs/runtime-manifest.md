# Runtime Manifest

Phase 7 adds a first formal runtime manifest layer so the verifier can refine static risk with controlled runtime facts.

## Supported inputs

- JSON
- YAML
- partial manifests
- unknown extra fields are tolerated

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
