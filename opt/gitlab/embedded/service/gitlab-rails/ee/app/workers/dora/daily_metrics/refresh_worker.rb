# frozen_string_literal: true

module Dora
  class DailyMetrics
    class RefreshWorker
      include ApplicationWorker

      data_consistency :always

      sidekiq_options retry: 3

      deduplicate :until_executing
      idempotent!
      queue_namespace :dora_metrics
      feature_category :dora_metrics
      loggable_arguments 0, 1

      def perform(environment_id, date, _event = nil)
        Environment.find_by_id(environment_id).try do |environment|
          ::Dora::DailyMetrics.refresh!(environment, Date.parse(date))
        end
      end
    end
  end
end
