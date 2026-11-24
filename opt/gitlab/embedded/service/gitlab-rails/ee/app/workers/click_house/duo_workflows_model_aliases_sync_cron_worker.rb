# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- matches the existing ClickHouse:: namespace used by every sibling
  class DuoWorkflowsModelAliasesSyncCronWorker
    include ApplicationWorker
    include ClickHouseWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :duo_agent_platform
    tags :clickhouse

    def perform
      return unless ::Gitlab::ClickHouse.configured?

      response = ::ClickHouse::DataIngestion::DuoWorkflowsModelAliasesSyncService.new.execute

      log_extra_metadata_on_done(:result, response.payload) if response.success?
    end
  end
end
