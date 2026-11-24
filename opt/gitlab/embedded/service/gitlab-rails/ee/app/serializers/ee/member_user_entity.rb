# frozen_string_literal: true

module EE
  module MemberUserEntity
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    prepended do
      unexpose :gitlab_employee
      expose :oncall_schedules, with: ::IncidentManagement::OncallScheduleEntity
      expose :escalation_policies, with: ::IncidentManagement::EscalationPolicyEntity

      expose :email, if: ->(user, options) do
        options[:current_user]&.can_admin_all_resources? ||
          user.can_read_email_enterprise_user?(options[:current_user], group: options[:source]&.root_ancestor)
      end

      expose :is_service_account, if: ->(user, _options) { user&.service_account? } do |user|
        user&.service_account?
      end

      def oncall_schedules
        return object.oncall_schedules.for_project(project_ids) unless object.oncall_schedules.loaded?

        user_schedules = object.oncall_schedules.to_a
        user_schedules.select { |schedule| project_ids.include?(schedule.project_id) }
      end

      def escalation_policies
        return object.escalation_policies.for_project(project_ids) unless object.escalation_policies.loaded?

        user_policies = object.escalation_policies
        user_policies.select { |policy| project_ids.include?(policy.project_id) }
      end
    end

    private

    # options[:source] is required to scope oncall schedules or policies
    # It should be either a Group or Project
    def project_ids
      strong_memoize(:project_ids) do
        next [] unless options[:source].present?

        options[:source].is_a?(Group) ? options[:source].project_ids : [options[:source].id]
      end
    end
  end
end
