# frozen_string_literal: true

module Analytics
  module ValueStreamDashboard
    class CountWorker
      include ApplicationWorker
      include CronjobQueue

      idempotent!

      data_consistency :sticky
      feature_category :value_stream_management

      CURSOR_KEY = 'value_stream_dashboard_count_cursor'
      CUTOFF_DAYS = 5

      def perform
        return unless should_perform?

        runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new

        cursor = load_cursor
        batch = Analytics::ValueStreamDashboard::Aggregation.load_batch(cursor)

        if batch.empty?
          persist_cursor(nil)
          return
        end

        ActiveRecord::Associations::Preloader.new(records: batch, associations: { namespace: :organization }).call

        batch.each do |aggregation|
          # `break` inside the block would only leave `with_context`, so the block returns whether to stop.
          stop = with_context(organization: aggregation.namespace.organization) do
            unless licensed?(aggregation)
              aggregation.update!(enabled: false)
              next false
            end

            service_response = Analytics::ValueStreamDashboard::TopLevelGroupCounterService
              .new(aggregation: aggregation, cursor: cursor, runtime_limiter: runtime_limiter)
              .execute

            cursor = service_response[:cursor]

            service_response[:result] == :interrupted || runtime_limiter.over_time?
          end

          break if stop
        end

        persist_cursor(cursor)
      end

      private

      def should_perform?
        Time.current.day >= (Time.current.end_of_month.day - CUTOFF_DAYS) &&
          License.feature_available?(:group_level_analytics_dashboard)
      end

      def load_cursor
        value = Gitlab::Redis::SharedState.with { |redis| redis.get(CURSOR_KEY) }
        return if value.nil?

        raw_cursor = Gitlab::Json.safe_parse(value).symbolize_keys
        Analytics::ValueStreamDashboard::TopLevelGroupCounterService.load_cursor(raw_cursor: raw_cursor)
      end

      def persist_cursor(cursor)
        if cursor.nil?
          Gitlab::Redis::SharedState.with { |redis| redis.del(CURSOR_KEY) }
        else
          Gitlab::Redis::SharedState.with { |redis| redis.set(CURSOR_KEY, Gitlab::Json.dump(cursor.dump)) }
        end
      end

      def licensed?(aggregation)
        aggregation.namespace.licensed_feature_available?(:group_level_analytics_dashboard)
      end
    end
  end
end
