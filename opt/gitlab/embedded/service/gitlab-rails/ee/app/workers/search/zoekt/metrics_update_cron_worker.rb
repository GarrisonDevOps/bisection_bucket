# frozen_string_literal: true

module Search
  module Zoekt
    class MetricsUpdateCronWorker
      include Gitlab::Utils::StrongMemoize
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      include CronjobQueue

      data_consistency :sticky
      urgency :throttled
      idempotent!
      deduplicate :until_executed

      def perform(metric = nil)
        return false unless ::Gitlab::CurrentSettings.zoekt_indexing_enabled?
        return false unless ::License.feature_available?(:zoekt_code_search)

        return initiate if metric.nil?

        Search::Zoekt::MetricsService.execute(metric.to_s)
      end

      private

      def initiate
        Search::Zoekt::MetricsService::METRICS.each do |metric|
          with_context(related_class: self.class) { self.class.perform_async(metric.to_s) }
        end
      end
    end
  end
end
