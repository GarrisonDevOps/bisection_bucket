# frozen_string_literal: true

module Search
  module Elastic
    class MetricsUpdateCronWorker
      include Gitlab::Utils::StrongMemoize
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- cronjob does not schedule other work

      data_consistency :always
      urgency :throttled
      idempotent!
      deduplicate :until_executed

      SETTING_ENABLED = 1
      SETTING_DISABLED = 0

      BOOLEAN_SETTINGS = %w[
        elasticsearch_pause_indexing
        elasticsearch_advanced_search_pause_indexing
        elasticsearch_indexing
        elasticsearch_search
        elasticsearch_requeue_workers
      ].freeze

      def perform
        report_boolean_metrics

        true
      end

      private

      def settings_attributes
        ::Gitlab::CurrentSettings.attributes
      end
      strong_memoize_attr :settings_attributes

      def report_boolean_metrics
        boolean_settings_gauge = ::Gitlab::Metrics.gauge(:search_advanced_boolean_settings,
          'Advanced search boolean settings', {}, :max)

        BOOLEAN_SETTINGS.each do |setting|
          boolean_settings_gauge.set({ name: setting },
            settings_attributes[setting] ? SETTING_ENABLED : SETTING_DISABLED)
        end
      end
    end
  end
end
