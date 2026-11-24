# frozen_string_literal: true

module Geo
  # Called by Geo::SyncWorker
  class SyncService
    include ::Gitlab::Utils::StrongMemoize

    attr_reader :replicable_name, :model_record_id

    def initialize(replicable_name, model_record_id)
      @replicable_name = replicable_name
      @model_record_id = model_record_id
    end

    def execute
      replicator.sync
    end

    private

    def replicator
      ::Gitlab::Geo::Replicator.for_replicable_params(replicable_name: replicable_name, replicable_id: model_record_id)
    end
    strong_memoize_attr :replicator
  end
end
