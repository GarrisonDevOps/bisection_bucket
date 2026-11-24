# frozen_string_literal: true

module Analytics
  module UsageTrends
    class CounterJobWorker
      TIMEOUT = 250.seconds

      extend ::Gitlab::Utils::Override
      include ApplicationWorker
      include CronjobChildWorker

      data_consistency :sticky

      sidekiq_options retry: 3

      feature_category :devops_reports
      urgency :low

      idempotent!

      def perform(measurement_identifier, min_id, max_id, recorded_at, partial_results = nil)
        query_scope = ::Analytics::UsageTrends::Measurement.identifier_query_mapping[measurement_identifier].call

        result = counter(query_scope, min_id, max_id, partial_results)

        # If the batch counter timed out, schedule a job to continue counting later
        if result[:status] == :timeout
          return self.class.perform_async(measurement_identifier, result[:continue_from], max_id, recorded_at, result[:partial_results])
        end

        if result[:status] != :completed
          track_dropped_measurement(measurement_identifier, result[:status], min_id, max_id, recorded_at)
          return
        end

        UsageTrends::Measurement.insert_all([{ recorded_at: recorded_at, count: result[:count], identifier: measurement_identifier }])
      end

      private

      # :bad_config and :cancelled return without a row, a retry or an error, so a
      # measurement that was dropped looks the same as one that was never scheduled.
      def track_dropped_measurement(measurement_identifier, status, min_id, max_id, recorded_at)
        fields = {
          measurement_identifier: measurement_identifier,
          measurement: ::Analytics::UsageTrends::Measurement.identifiers.key(measurement_identifier),
          drop_reason: status.to_s,
          min_id: min_id,
          max_id: max_id,
          recorded_at: recorded_at
        }

        fields.each { |key, value| log_extra_metadata_on_done(key, value) }
        dropped_measurement_counter.increment(reason: status.to_s)
      end

      def dropped_measurement_counter
        Gitlab::Metrics.counter(
          :gitlab_usage_trends_measurement_dropped_total,
          'Usage trends measurements dropped by the batch counter before a row was written'
        )
      end

      def counter(query_scope, min_id, max_id, partial_results)
        return { status: :completed, count: 0 } if min_id.nil? || max_id.nil? # table is empty

        Gitlab::Database::BatchCount.batch_count_with_timeout(query_scope, start: min_id, finish: max_id, timeout: TIMEOUT, partial_results: partial_results)
      end
    end
  end
end
