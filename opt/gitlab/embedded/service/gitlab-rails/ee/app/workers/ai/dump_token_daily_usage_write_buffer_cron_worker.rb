# frozen_string_literal: true

module Ai
  class DumpTokenDailyUsageWriteBufferCronWorker
    include ApplicationWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :always # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- reads organization IDs that a replica may not have replayed
    feature_category :ai_abstraction_layer

    def perform
      result = ::Ai::TokenDailyUsages::DrainBufferService.new.execute

      log_extra_metadata_on_done(:result, result.payload)
    end
  end
end
