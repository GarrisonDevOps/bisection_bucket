# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class CreateProjectWarnModePushSettingsAuditEventService
      include Gitlab::Utils::StrongMemoize
      include Security::ScanResultPolicies::HumanizationHelpers

      AUDIT_EVENT = 'policy_warn_mode_push_settings_overrides'

      def initialize(project, policy)
        @project = project
        @policy = policy
      end

      def execute
        return unless policy_management_project
        return unless policy.warn_mode? && overrides.any?

        author = find_or_create_security_policy_bot

        ::Gitlab::Audit::Auditor.audit(initial_audit_context(author)) do
          overrides.each { |override| policy.push_audit_event(message(override), after_commit: false) }
        end
      end

      private

      attr_reader :project, :policy

      def initial_audit_context(author)
        {
          name: AUDIT_EVENT,
          scope: policy_management_project,
          target: policy,
          author: author
        }
      end

      def policy_management_project
        policy.security_policy_management_project
      end
      strong_memoize_attr :policy_management_project

      def message(override)
        affected_names = override.protected_branches.map { |branch| %("#{branch.name}") }.join(", ")
        humanized_setting = humanized_approval_setting(override.attribute)

        "In project (#{project.full_path}), the approval settings in a security policy in warn mode will " \
          "override the branch protections in #{affected_names}: #{humanized_setting}"
      end

      def find_or_create_security_policy_bot
        project.security_policy_bot || create_security_policy_bot!
      end

      def create_security_policy_bot!
        Security::Orchestration::CreateBotService.new(project, nil, skip_authorization: true).execute.user
      end

      def overrides
        ::Security::ScanResultPolicies::PushSettingsOverrides.new(
          project: project,
          warn_mode_policies: [policy]
        ).all
      end
      strong_memoize_attr :overrides
    end
  end
end
