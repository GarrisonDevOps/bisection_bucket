# frozen_string_literal: true

module Security
  class UnassignRedundantPolicyConfigurationsWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    def self.idempotency_arguments(arguments)
      group_id, policy_project_id, _ = arguments

      [group_id, policy_project_id]
    end

    def perform(group_id, policy_project_id, user_id)
      group = Group.find_by_id(group_id) || return
      user = User.find_by_id(user_id) || return

      # rubocop:disable CodeReuse/ActiveRecord -- find_each
      affected_configurations(group, policy_project_id).find_each(batch_size: 100) do |config|
        # rubocop:enable CodeReuse/ActiveRecord
        ::Security::Orchestration::UnassignService
          .new(container: config.project || config.namespace, current_user: user)
          .execute(delete_bot: false)
      end
    end

    private

    def affected_configurations(group, policy_project_id)
      Security::OrchestrationPolicyConfiguration
        .for_management_project_within_descendants(policy_project_id, group)
        .eager_load(:project, :namespace) # rubocop:disable CodeReuse/ActiveRecord -- avoids N+1 queries
    end
  end
end
