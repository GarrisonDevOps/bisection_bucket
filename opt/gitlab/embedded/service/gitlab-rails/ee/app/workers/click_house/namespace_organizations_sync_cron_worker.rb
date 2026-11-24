# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- matches the existing ClickHouse:: namespace used by every sibling
  class NamespaceOrganizationsSyncCronWorker
    include ApplicationWorker
    include ClickHouseWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management
    tags :clickhouse

    def perform
      return unless ::Gitlab::ClickHouse.configured?

      response = ::ClickHouse::DataIngestion::NamespaceOrganizationsSyncService.new.execute

      log_extra_metadata_on_done(:result, response.payload) if response.success?
    end
  end
end
