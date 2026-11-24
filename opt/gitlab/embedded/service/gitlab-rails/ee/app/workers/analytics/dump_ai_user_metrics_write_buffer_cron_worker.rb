# frozen_string_literal: true

module Analytics
  class DumpAiUserMetricsWriteBufferCronWorker
    include ApplicationWorker
    include WriteBufferProcessorWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management

    MAX_RUNTIME = 200.seconds
    BATCH_SIZE = 1000

    def initialize(*)
      super
      @model = Ai::UserMetrics
      @upsert_options = {
        unique_by: %i[user_id],
        on_duplicate: Arel.sql(<<~SQL.squish)
          last_duo_activity_on = GREATEST(excluded.last_duo_activity_on, ai_user_metrics.last_duo_activity_on)
        SQL
      }
    end
  end
end
