# frozen_string_literal: true

module UsageEvents
  class DumpWriteBufferCronWorker
    include ApplicationWorker
    include ::Analytics::WriteBufferProcessorWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management

    MAX_RUNTIME = 200.seconds
    BATCH_SIZE = 1000

    def initialize(*)
      super
      @model = Ai::UsageEvent
      @upsert_options = { unique_by: %i[namespace_id user_id event timestamp organization_id] }
    end

    private

    def prepare_attributes(valid_objects)
      attributes = super

      uniq_tuple = upsert_options[:unique_by].map(&:to_s)

      # Deduplicate rows with the same uniqueness tuple.
      attributes.group_by { |attr| attr.slice(*uniq_tuple) }.values.map(&:first)
    end
  end
end
