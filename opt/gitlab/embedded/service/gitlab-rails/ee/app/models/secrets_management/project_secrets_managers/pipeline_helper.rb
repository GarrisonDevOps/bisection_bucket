# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsManagers
    module PipelineHelper
      extend ActiveSupport::Concern

      def ci_auth_path
        [
          full_project_namespace_path,
          'auth',
          ci_auth_mount,
          'cel',
          'login'
        ].join('/')
      end

      def pipeline_auth_cel_program(project_id)
        {
          variables: [
            { name: "expected_pid", expression: %("#{project_id}") },
            { name: "pid", expression: %q(('project_id' in claims) ? string(claims['project_id']) : "") },
            { name: "uid", expression: %q(('user_id' in claims) ? string(claims['user_id']) : "") },
            { name: "aud", expression: %q(('aud' in claims) ? string(claims['aud']) : "") },
            { name: "expected_aud", expression: %("#{aud}") },
            { name: "sub", expression: %q(('sub' in claims) ? claims['sub'] : "") },
            { name: "scope",
              expression: %q(('secrets_manager_scope' in claims) ? string(claims['secrets_manager_scope']) : "") },
            { name: "correlation_id",
              expression: %q(('correlation_id' in claims) ? string(claims['correlation_id']) : "") },
            { name: "namespace_id",
              expression: %q(('namespace_id' in claims) ? string(claims['namespace_id']) : "") },
            { name: "ref_type",
              expression: %q(('ref_type' in claims) ? string(claims['ref_type']) : "") },
            { name: "ref",
              expression: %q(('ref' in claims) ? string(claims['ref']) : "") },
            { name: "environment",
              expression: %q(('environment' in claims) ? string(claims['environment']) : "") },
            { name: "env_hex",
              expression: %q(environment != "" ? "%x".format([environment]) : "") },
            { name: "ref_hex",
              expression: %q(ref != "" ? "%x".format([ref]) : "") },
            { name: "global_policy",
              expression: %q("pipelines/global") },
            { name: "env_policy",
              expression: %q(environment != "" ? "pipelines/env/" + env_hex : "") },
            { name: "branch_policy",
              expression: %q(ref_type == "branch" && ref != "" ? "pipelines/branch/" + ref_hex : "") },
            { name: "combined_policy",
              # rubocop:disable Layout/LineLength -- CEL expression readability
              expression: %q(ref_type == "branch" && ref != "" && environment != "" ? "pipelines/combined/env/" + env_hex + "/branch/" + ref_hex : "") },
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
            pid != expected_pid ? "token project_id does not match project" :
            uid == "" ? "missing user_id" :
            aud == "" ? "missing audience" :
            aud != expected_aud ? "audience validation failed" :
            pb.Auth{
              display_name: "pipeline:" + pid,
              alias: logical.Alias { name: "pipeline:" + pid },
              policies: [global_policy] + (env_policy != "" ? [env_policy] : []) + (branch_policy != "" ? [branch_policy] : []) + (combined_policy != "" ? [combined_policy] : []),
              metadata: {
                "correlation_id": correlation_id,
                "user_id": uid,
                "project_id": pid,
                "namespace_id": namespace_id,
                "pipeline_id": pipeline_id,
                "job_id": job_id
              }
            }
          CEL
        }
      end

      def ci_secrets_mount_full_path
        [
          full_project_namespace_path,
          ci_secrets_mount_path
        ].compact.join('/')
      end

      def ci_policy_name(environment, branch)
        if environment != "*" && branch != "*"
          ci_policy_name_combined(environment, branch)
        elsif environment != "*"
          ci_policy_name_env(environment)
        elsif branch != "*"
          ci_policy_name_branch(branch)
        else
          ci_policy_name_global
        end
      end

      def ci_policy_name_global
        %w[pipelines global].compact.join('/')
      end

      def ci_policy_name_env(environment)
        ["pipelines", "env", hex(environment)].compact.join('/')
      end

      def ci_policy_name_branch(branch)
        ["pipelines", "branch", hex(branch)].compact.join('/')
      end

      def ci_policy_name_combined(environment, branch)
        ["pipelines", "combined", "env", hex(environment), "branch", hex(branch)].compact.join('/')
      end
    end
  end
end
