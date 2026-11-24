# frozen_string_literal: true

# Deprecated: no longer enqueued. Removal is tracked in
# https://gitlab.com/gitlab-org/gitlab/-/work_items/639682
class ImportIssuesCsvWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  idempotent!
  feature_category :team_planning
  worker_resource_boundary :cpu
  weight 2

  # Only releases the upload of a job enqueued before the import endpoint was removed.
  def perform(_current_user_id, _project_id, upload_id)
    Upload.find_by_id(upload_id)&.destroy
  end
end
