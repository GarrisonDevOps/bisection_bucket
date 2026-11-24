# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Validate
            module Abilities
              extend ::Gitlab::Utils::Override

              override :perform!
              def perform!
                # Validate that ondemand_dast_scan source is only used with custom content.
                # This prevents abuse if a future pipeline creation path accidentally
                # allows users to control the source parameter. Legitimate DAST scans
                # always provide content via AppSec::Dast::Scans::RunService.
                if command.ondemand_dast_scan? && command.content.blank?
                  return error('On-demand DAST scan pipelines must provide CI configuration content')
                end

                # We check for `builds_enabled?` here so that this error does
                # not get produced before the "pipelines are disabled" error.
                if project.builds_enabled? && mirror_update? && !project.mirror_trigger_builds?
                  return error('Pipeline is disabled for mirror updates')
                end

                super
              end

              private

              override :allowed_to_run_pipeline?
              def allowed_to_run_pipeline?
                # On-demand DAST scans are not subject to branch protection.
                # This permission is prevented when the command is not a DAST scan.
                # See ee/app/policies/ee/gitlab/ci/pipeline/chain/command_policy.rb.
                return true if can?(current_user, :create_on_demand_dast_scan, command)

                super || allowed_via_protected_branch_bypass?
              end

              override :allowed_to_create_pipeline?
              def allowed_to_create_pipeline?
                super || can?(current_user, :create_on_demand_dast_scan, command)
              end

              # Mirror the approval policy bypass that let the push reach a protected
              # branch (see EE::Gitlab::Checks::BranchCheck); otherwise the push
              # pipeline is silently discarded. Scoped to push-created pipelines: the
              # push path already evaluated and audited the bypass, so auditing is off
              # here. Other sources (web, schedule, api) never run the push path, so
              # they must not silently inherit the bypass without an audit trail.
              def allowed_via_protected_branch_bypass?
                return false unless current_user && command.branch? && command.source&.to_sym == :push

                granted = ::Security::ScanResultPolicies::CombinedBypassChecker.new(
                  project: project,
                  user_access: user_access,
                  branch_name: command.ref,
                  push_options: command.push_options,
                  audit: false
                ).protected_branch_bypass_granted?

                if granted && ::Feature.enabled?(:record_security_policy_protected_branch_bypass, project)
                  command.security_policy_protected_branch_bypassed = true
                end

                granted
              end

              def mirror_update?
                # - command.mirror_update is for in-place pipeline creation within pull mirroring.
                # - gitaly_context is for pipelines created from post-receive hooks
                command.mirror_update ||
                  command.gitaly_context&.fetch(::Projects::UpdateMirrorService::GITALY_CONTEXT_KEY, false)
              end
            end
          end
        end
      end
    end
  end
end
