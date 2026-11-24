# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ScheduledScansNotEnforcedAuditor
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, author:, schedule:, branch:)
        @project = project
        @author = author
        @schedule = schedule
        @branch = branch
      end

      def audit
        return unless schedule && project

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      private

      attr_reader :project, :author, :schedule, :branch

      def audit_context
        {
          name: event_name,
          author: schedule_author,
          scope: security_policy_management_project,
          target: schedule,
          target_details: schedule.id.to_s,
          message: event_message,
          additional_details: additional_details
        }
      end

      def event_name
        'security_policy_scheduled_scans_not_enforced'
      end

      def event_message
        "Schedule: #{schedule.id} created by security policies could not be enforced"
      end

      def security_policy_management_project
        schedule.security_orchestration_policy_configuration.security_policy_management_project
      end

      def additional_details
        {
          target_branch: branch,
          project_id: project.id,
          project_name: project.name,
          project_full_path: project.full_path,
          skipped_policy: skipped_policy
        }.compact
      end

      def skipped_policy
        { name: schedule.policy&.dig(:name), policy_type: schedule.policy_type }
      end

      def schedule_author
        author || Gitlab::Audit::DeletedAuthor.new(
          id: Gitlab::Audit::NullAuthor::UNKNOWN_USER_AUTHOR_ID, name: 'Unknown User'
        )
      end
      strong_memoize_attr :schedule_author
    end
  end
end
