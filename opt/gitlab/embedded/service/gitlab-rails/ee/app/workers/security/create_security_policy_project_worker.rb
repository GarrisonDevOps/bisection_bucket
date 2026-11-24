# frozen_string_literal: true

module Security
  class CreateSecurityPolicyProjectWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    urgency :high
    deduplicate :until_executed # Avoid race condition in creating security policy projects
    idempotent!

    def perform(project_or_group_path, current_user_id)
      container = Routable.find_by_full_path(project_or_group_path)
      user = User.find_by_id(current_user_id)

      errors = [].tap do |errors|
        errors << 'Group or project not found.' if container.blank?
        errors << 'User not found.' if user.blank?
      end

      if errors.any?
        error(errors, container)

        return
      end

      service_result = ::Security::SecurityOrchestrationPolicies::ProjectCreateService
        .new(container: container, current_user: user)
        .execute

      GraphqlTriggers.security_policy_project_created(
        container,
        service_result[:status],
        service_result[:policy_project],
        [service_result[:message]].compact
      )
    end

    private

    def error(messages, container = nil)
      GraphqlTriggers.security_policy_project_created(
        container,
        :error,
        nil,
        messages
      )
    end
  end
end
