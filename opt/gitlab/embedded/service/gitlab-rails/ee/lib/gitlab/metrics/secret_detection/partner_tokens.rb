# frozen_string_literal: true

module Gitlab
  module Metrics
    module SecretDetection
      module PartnerTokens
        extend ActiveSupport::Concern

        PARTNER_API_DURATION = :validity_check_partner_api_duration_seconds
        PARTNER_API_REQUESTS = :validity_check_partner_api_requests_total
        NETWORK_ERRORS = :validity_check_network_errors_total
        RATE_LIMIT_HITS = :validity_check_rate_limit_hits_total

        class << self
          include Gitlab::Utils::StrongMemoize

          def observe_api_duration(duration, partner:)
            api_duration_histogram.observe(
              { partner: partner },
              duration
            )
          end

          def increment_api_requests(partner:, status:, error_type: 'none')
            api_requests_counter.increment(
              { partner: partner, status: status, error_type: error_type }
            )
          end

          def increment_network_errors(partner:, error_class:)
            network_errors_counter.increment(
              { partner: partner, error_class: error_class }
            )
          end

          def increment_rate_limit_hits(limit_type:)
            rate_limit_hits_counter.increment(
              { limit_type: limit_type }
            )
          end

          private

          def rate_limit_hits_counter
            ::Gitlab::Metrics.counter(
              RATE_LIMIT_HITS,
              'Total rate limit hits during token verification'
            )
          end

          def api_duration_histogram
            ::Gitlab::Metrics.histogram(
              PARTNER_API_DURATION,
              'Partner API response time in seconds',
              {},
              [0.1, 0.25, 0.5, 1, 2, 5, 10]
            )
          end

          def api_requests_counter
            ::Gitlab::Metrics.counter(
              PARTNER_API_REQUESTS,
              'Total partner API verification requests'
            )
          end

          def network_errors_counter
            ::Gitlab::Metrics.counter(
              NETWORK_ERRORS,
              'Total network errors during partner API calls'
            )
          end
        end
      end
    end
  end
end
