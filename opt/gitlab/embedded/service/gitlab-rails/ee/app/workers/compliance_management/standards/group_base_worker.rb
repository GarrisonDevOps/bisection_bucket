# frozen_string_literal: true

module ComplianceManagement
  module Standards
    class GroupBaseWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      urgency :low

      feature_category :compliance_management

      # This worker expects the following keys passed inside the args hash:
      # 'group_id', 'user_id' (optional), 'track_progress' (optional)
      def perform(args = {})
        group_id = args['group_id']
        user_id = args['user_id']
        track_progress = args['track_progress']
        group = Group.find_by_id(group_id)
        user = User.find_by_id(user_id)

        return unless group

        group.all_projects.each_batch do |projects|
          worker_class.bulk_perform_async_with_contexts(
            projects,
            arguments_proc: ->(project) do
              { 'project_id' => project.id, 'user_id' => user&.id, 'track_progress' => track_progress }
            end,
            context_proc: ->(project) { { project: project } }
          )
        end
      end
    end
  end
end
