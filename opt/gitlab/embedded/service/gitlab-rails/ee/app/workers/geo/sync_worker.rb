# frozen_string_literal: true

module Geo
  # Enqueued by RegistrySyncWorker and RepositoryRegistrySyncWorker
  # to perform syncs. These syncs are distinct from Geo update events
  # because these syncs do not begin by marking the registry pending.
  class SyncWorker
    include ApplicationWorker
    include GeoQueue
    include ::Gitlab::Geo::LogHelpers

    idempotent!
    worker_has_external_dependencies!
    data_consistency :sticky
    sidekiq_options retry: false, dead: false
    loggable_arguments 0, 1

    def perform(replicable_name, model_record_id)
      parent_correlation_id = Labkit::Correlation::CorrelationId.current_id
      new_correlation_id = Labkit::Context.new.correlation_id

      Labkit::Correlation::CorrelationId.use_id(new_correlation_id) do
        log_info(
          'Sync starting with new correlation_id for filtering',
          replicable_name: replicable_name,
          model_record_id: model_record_id,
          parent_correlation_id: parent_correlation_id
        )

        Geo::SyncService.new(replicable_name, model_record_id).execute
      end
    end
  end
end
