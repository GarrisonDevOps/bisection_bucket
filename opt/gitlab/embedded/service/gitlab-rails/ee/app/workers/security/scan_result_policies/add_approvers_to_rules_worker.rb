# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AddApproversToRulesWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      feature_category :security_policy_management
      idempotent!

      concurrency_limit -> { 200 }

      class << self
        def projects(event)
          project_ids = Array.wrap(event.data[:project_id] || event.data[:project_ids])

          Project.id_in(project_ids).with_scan_result_policy_reads
        end

        def dispatch?(event)
          projects(event).any? { |project| process_project?(project) }

          # TODO: Add check if we have any rules in defined policies that requires this worker to perform
          # TODO: This will be possible after delivery of https://gitlab.com/groups/gitlab-org/-/epics/9971
        end

        def process_project?(project)
          project.has_approval_policy_rules? &&
            ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        end
      end

      def handle_event(event)
        user_ids = event.data[:user_ids]
        return if user_ids.blank?

        configurations_by_id = {}
        self.class.projects(event)
          .with_namespace.with_group.with_compliance_framework_settings
          .find_each do |project|
          next unless self.class.process_project?(project)

          Security::ScanResultPolicies::AddApproversToRulesService
            .new(project: project, configurations_by_id: configurations_by_id)
            .execute(user_ids)
        end
      end
    end
  end
end
