# frozen_string_literal: true

module Gitlab
  module Instrumentation
    class ElasticsearchTransport
      extend RequestStoreCounters

      ELASTICSEARCH_REQUEST_COUNT = :elasticsearch_request_count
      ELASTICSEARCH_CALL_DURATION = :elasticsearch_call_duration
      ELASTICSEARCH_CALL_DETAILS = :elasticsearch_call_details
      ELASTICSEARCH_TIMED_OUT_COUNT = :elasticsearch_timed_out_count

      module Interceptor
        def perform_request(method, path, params = {}, body = nil, headers = nil)
          start = Time.now
          headers = (headers || {})
            .reverse_merge({ 'X-Opaque-Id': Labkit::Correlation::CorrelationId.current_or_new_id })
          response = super
        rescue *::Gitlab::Search::Client::AUTHORIZATION_ERRORS => e
          ::Gitlab::ErrorTracking.track_exception(e)

          raise ::Gitlab::Search::Client::AuthorizationError, e.message
        rescue *::Gitlab::Search::Client::TIMEOUT_ERRORS => e
          ::Gitlab::ErrorTracking.track_exception(e)

          raise ::Elastic::TimeoutError, e.message
        rescue *::Gitlab::Search::Client::TRANSPORT_ERRORS => e
          ::Gitlab::ErrorTracking.track_exception(e)

          raise ::Gitlab::Search::Client::ConnectionError, e.message
        ensure
          if ::Gitlab::SafeRequestStore.active?
            duration = (Time.now - start)

            ::Gitlab::Instrumentation::ElasticsearchTransport.increment_request_count

            if response&.body && response.body.is_a?(Hash) && response.body['timed_out']
              ::Gitlab::Instrumentation::ElasticsearchTransport.increment_timed_out_count
            end

            ::Gitlab::Instrumentation::ElasticsearchTransport.add_duration(duration)
            ::Gitlab::Instrumentation::ElasticsearchTransport.add_call_details(duration, method, path, params, body)
          end
        end
      end

      def self.get_request_count
        counter_value(ELASTICSEARCH_REQUEST_COUNT)
      end

      def self.increment_request_count
        increment_counter(ELASTICSEARCH_REQUEST_COUNT)
      end

      def self.detail_store
        ::Gitlab::SafeRequestStore[ELASTICSEARCH_CALL_DETAILS] ||= []
      end

      def self.query_time
        counter_duration(ELASTICSEARCH_CALL_DURATION)
      end

      def self.add_duration(duration)
        increment_counter(ELASTICSEARCH_CALL_DURATION, duration)
      end

      def self.increment_timed_out_count
        increment_counter(ELASTICSEARCH_TIMED_OUT_COUNT)
      end

      def self.get_timed_out_count
        counter_value(ELASTICSEARCH_TIMED_OUT_COUNT)
      end

      def self.add_call_details(duration, method, path, params, body)
        return unless Gitlab::PerformanceBar.enabled_for_request?

        detail_store << {
          method: method,
          path: path,
          params: params,
          body: body,
          duration: duration,
          backtrace: ::Gitlab::BacktraceCleaner.clean_backtrace(caller)
        }
      end
    end
  end
end
