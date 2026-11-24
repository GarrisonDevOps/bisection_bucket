# frozen_string_literal: true

class DeleteMergedBranchesWorker
  include ApplicationWorker

  data_consistency :sticky

  sidekiq_options retry: 3

  idempotent!
  deduplicate :until_executing

  # Each deleted branch fans out high-urgency PostReceive and ProjectCache jobs
  concurrency_limit -> { 20 }

  feature_category :source_code_management

  def perform(project_id, user_id)
    begin
      project = Project.find(project_id)
    rescue ActiveRecord::RecordNotFound
      return
    end

    user = User.find_by_id(user_id)
    return unless user

    begin
      ::Branches::DeleteMergedService.new(project, user).execute
    rescue Gitlab::Access::AccessDeniedError
    end
  end
end
