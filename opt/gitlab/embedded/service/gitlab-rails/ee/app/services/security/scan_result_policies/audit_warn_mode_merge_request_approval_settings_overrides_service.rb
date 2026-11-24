# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AuditWarnModeMergeRequestApprovalSettingsOverridesService
      include Gitlab::Utils::StrongMemoize
      include Security::ScanResultPolicies::HumanizationHelpers

      AUDIT_EVENT = 'policy_warn_mode_merge_request_approval_settings_overrides'

      def initialize(merge_request)
        @merge_request = merge_request
        @project = merge_request.project
      end

      def execute
        ensure_policy_bot_exists!

        overrides.each do |override|
          policies_by_policy_project = override.security_policies.group_by(&:security_policy_management_project)

          ::Gitlab::Audit::Auditor.audit(initial_audit_context) do
            policies_by_policy_project.each do |(policy_project, policies)|
              policies.each do |policy|
                event = {
                  message: message(override),
                  target: policy,
                  scope: policy_project
                }

                policy.push_audit_event(event, after_commit: false)
              end
            end
          end
        end
      end

      private

      attr_reader :merge_request, :project

      def initial_audit_context
        {
          name: AUDIT_EVENT,
          author: project.security_policy_bot,
          # We need to set a `target` and `scope` for feature availability checks.
          # We override both when we push the individual audit events.
          target: project,
          scope: project
        }
      end

      def message(override)
        humanized_override = humanized_approval_setting(override.attribute)

        "The merge request #{merge_request.to_reference(full: true)} is affected by a warn mode policy " \
          "that sets more restrictive `approval_settings` when enforced: #{humanized_override}"
      end

      def ensure_policy_bot_exists!
        return if project.security_policy_bot

        Security::Orchestration::CreateBotService.new(project, nil, skip_authorization: true).execute.user
      end

      def overrides
        ::Security::ScanResultPolicies::ApprovalSettingsOverrides.new(
          project: project,
          warn_mode_policies: violated_warn_mode_policies,
          enforced_policies: violated_enforced_policies
        ).all
      end

      def violated_warn_mode_policies
        violated_approval_policies.select(&:warn_mode?)
      end

      def violated_enforced_policies
        violated_approval_policies.reject(&:warn_mode?)
      end

      def violated_approval_policies
        merge_request
          .security_policies_through_violations
          .type_approval_policy
          .including_security_policy_management_project
      end
      strong_memoize_attr :violated_approval_policies
    end
  end
end
