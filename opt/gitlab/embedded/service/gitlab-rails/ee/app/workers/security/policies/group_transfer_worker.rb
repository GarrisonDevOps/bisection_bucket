# frozen_string_literal: true

module Security
  module Policies
    class GroupTransferWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed

      concurrency_limit -> { 200 }

      feature_category :security_policy_management

      BATCH_SIZE = 250

      def perform(group_id, current_user_id)
        group = Group.find_by_id(group_id) || return

        return unless ::Security::PolicyAvailability.available?(group, :security_orchestration_policies)

        group.all_project_ids.each_batch(of: BATCH_SIZE) do |projects|
          Security::Policies::GroupProjectTransferWorker.bulk_perform_async_with_contexts(
            projects,
            arguments_proc: ->(project) { [project.id, current_user_id] },
            context_proc: ->(_) { { namespace: group } }
          )
        end
      end
    end
  end
end
