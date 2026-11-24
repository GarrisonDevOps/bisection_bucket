# frozen_string_literal: true

module MergeRequests
  class RemoveUserApprovalRulesWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :code_review_workflow
    idempotent!

    def handle_event(event)
      user_ids = event.data[:user_ids]
      return if user_ids.blank?

      project_id = event.data[:project_id]
      project = Project.find_by_id(project_id)

      unless project
        logger.info(structured_payload(message: 'Project not found.', project_id: project_id))
        return
      end

      ApprovalRules::UserRulesDestroyService.new(project: project).execute(user_ids)
    end
  end
end
