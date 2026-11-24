# frozen_string_literal: true

module Ci
  module Runners
    # rubocop: disable Scalability/IdempotentWorker -- this worker sends out emails
    class ExportUsageCsvWorker
      include ApplicationWorker

      data_consistency :delayed

      sidekiq_options retry: 3

      feature_category :fleet_visibility
      worker_resource_boundary :cpu
      loggable_arguments 0, 1

      def perform(current_user_id, params)
        params.symbolize_keys!

        user = User.find(current_user_id)
        from_date = Date.parse(params[:from_date])
        to_date = Date.parse(params[:to_date])
        result = Ci::Runners::SendUsageCsvService.new(
          current_user: user, from_date: from_date, to_date: to_date,
          **params.slice(:runner_type, :full_path, :max_project_count)
        ).execute
        log_extra_metadata_on_done(:status, result.status)
        log_extra_metadata_on_done(:message, result.message) if result.message
        log_extra_metadata_on_done(:csv_status, result.payload[:status]) if result.payload[:status]
      end
    end
    # rubocop: enable Scalability/IdempotentWorker
  end
end
