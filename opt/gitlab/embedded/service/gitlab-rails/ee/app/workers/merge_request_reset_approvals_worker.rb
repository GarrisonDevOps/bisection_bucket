# frozen_string_literal: true

class MergeRequestResetApprovalsWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  feature_category :source_code_management
  urgency :high
  worker_resource_boundary :cpu
  loggable_arguments 2, 3, 4

  def perform(project_id, user_id, ref, newrev, oldrev = nil)
    project = Project.find_by_id(project_id)
    return unless project

    user = User.find_by_id(user_id)
    return unless user

    result = MergeRequests::ResetApprovalsService.new(project: project, current_user: user)
      .execute(ref, newrev, oldrev: oldrev)
    return unless result.is_a?(Hash)

    total_duration = result.values.sum
    hash_with_total = result.merge(reset_approvals_service_total_duration_s: total_duration)

    hash_with_total.transform_values! do |duration|
      duration.round(Gitlab::InstrumentationHelper::DURATION_PRECISION)
    end

    log_hash_metadata_on_done(hash_with_total)
  end
end
