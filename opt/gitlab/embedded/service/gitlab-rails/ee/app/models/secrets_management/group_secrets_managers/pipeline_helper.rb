# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsManagers
    module PipelineHelper
      extend ActiveSupport::Concern

      def ci_auth_path
        [
          full_group_namespace_path,
          'auth',
          ci_auth_mount,
          'cel',
          'login'
        ].compact.join('/')
      end

      def ci_secrets_mount_full_path
        [
          full_group_namespace_path,
          ci_secrets_mount_path
        ].compact.join('/')
      end

      # Group-specific policy naming (environment + protected/unprotected flag)
      # The protected flag is based on whether the branch is protected (ref_protected claim)
      # similar to how CI variables work, NOT based on protected environments
      def ci_policy_name_for_environment(environment, protected:)
        protection_level = protected ? "protected" : "unprotected"
        env_part = environment == "*" ? "global" : "env/#{hex(environment)}"

        ["pipelines", "combined", protection_level, env_part].join('/')
      end

      # Pipeline auth CEL program - validates pipeline authentication
      # Validates project belongs to group via project_group_ids claim (Issue #563038)
      # This claim contains all parent group IDs for a project, enabling proper
      # inheritance validation for group-level secrets.
      def pipeline_auth_cel_program(group_id)
        {
          variables: [
            { name: "expected_gid", expression: %("#{group_id}") },
            { name: "project_gids",
              expression: %q(('project_group_ids' in claims) ? claims['project_group_ids'] : []) },
            { name: "uid", expression: %q(('user_id' in claims) ? string(claims['user_id']) : "") },
            { name: "pid", expression: %q(('project_id' in claims) ? string(claims['project_id']) : "") },
            { name: "aud", expression: %q(('aud' in claims) ? claims['aud'] : "") },
            { name: "expected_aud", expression: %("#{aud}") },
            { name: "sub", expression: %q(('sub' in claims) ? claims['sub'] : "") },
            { name: "scope",
              expression: %q(('secrets_manager_scope' in claims) ? string(claims['secrets_manager_scope']) : "") },
            { name: "correlation_id",
              expression: %q(('correlation_id' in claims) ? string(claims['correlation_id']) : "") },
            { name: "ref_protected",
              expression: %q(('ref_protected' in claims) ? string(claims['ref_protected']) : "false") },
            { name: "environment",
              expression: %q(('environment' in claims) ? string(claims['environment']) : "") },
            { name: "protection_level",
              expression: %q(ref_protected == "true" ? "protected" : "unprotected") },
            { name: "env_hex",
              expression: %q(environment != "" ? "%x".format([environment]) : "") },
            { name: "global_policy",
              expression: %q("pipelines/combined/" + protection_level + "/global") },
            { name: "env_policy",
              expression: %q(environment != "" ? "pipelines/combined/" + protection_level + "/env/" + env_hex : "") },
            { name: "unprotected_global_policy",
              expression: %q(protection_level == "protected" ? "pipelines/combined/unprotected/global" : "") },
            { name: "unprotected_env_policy",
              # rubocop:disable Layout/LineLength -- CEL expression readability
              expression: %q(protection_level == "protected" && environment != "" ? "pipelines/combined/unprotected/env/" + env_hex : "") },
            # rubocop:enable Layout/LineLength
            { name: "pipeline_id",
              expression: %q(('pipeline_id' in claims) ? string(claims['pipeline_id']) : "") },
            { name: "job_id",
              expression: %q(('job_id' in claims) ? string(claims['job_id']) : "") }
          ],
          expression: <<~'CEL'.strip
            sub == "" ? "missing subject" :
            !sub.startsWith("project_path:") ? "invalid subject for pipeline authentication" :
            scope == "" ? "missing secrets_manager_scope" :
            scope != "pipeline" ? "invalid secrets_manager_scope" :
            pid == "" ? "missing project_id" :
            uid == "" ? "missing user_id" :
            aud == "" ? "missing audience" :
            aud != expected_aud ? "audience validation failed" :
            project_gids.size() == 0 ? "missing project_group_ids claim" :
            !project_gids.exists(g, string(g) == expected_gid) ?
              "project does not belong to group" :
            pb.Auth{
              display_name: "pipeline:" + pid,
              alias: logical.Alias { name: "pipeline:" + pid },
              policies: [global_policy] + (unprotected_global_policy != "" ? [unprotected_global_policy] : []) + (env_policy != "" ? [env_policy] : []) + (unprotected_env_policy != "" ? [unprotected_env_policy] : []),
              metadata: {
                "correlation_id": correlation_id,
                "user_id": uid,
                "project_id": pid,
                "group_id": expected_gid,
                "pipeline_id": pipeline_id,
                "job_id": job_id
              }
            }
          CEL
        }
      end
    end
  end
end
