# frozen_string_literal: true

class ExportCsvWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  feature_category :team_planning
  worker_resource_boundary :cpu
  loggable_arguments 2

  # No-op, kept so already queued jobs can drain before the class is removed.
  def perform(current_user_id, project_id, params); end
end
