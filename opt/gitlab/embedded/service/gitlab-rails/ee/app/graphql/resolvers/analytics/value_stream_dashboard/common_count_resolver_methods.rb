# frozen_string_literal: true

module Resolvers
  module Analytics
    module ValueStreamDashboard
      module CommonCountResolverMethods
        extend ActiveSupport::Concern

        CACHE_TTL = 15.minutes
        MAX_TIMEFRAME_DAYS = 400

        included do
          include Gitlab::Graphql::Authorize::AuthorizeResource
          type ::Types::Analytics::ValueStreamDashboard::CountType, null: true
          authorizes_object!

          argument :timeframe, Types::TimeframeInputType,
            required: true,
            description: 'Counts recorded during this time frame, usually from beginning of ' \
              'the month until the end of the month (the system runs monthly aggregations). ' \
              "Maximum range is #{MAX_TIMEFRAME_DAYS} days."

          def ready?(**args)
            timeframe = args[:timeframe]
            if (timeframe[:end] - timeframe[:start]) > MAX_TIMEFRAME_DAYS
              raise Gitlab::Graphql::Errors::ArgumentError, "maximum timeframe is #{MAX_TIMEFRAME_DAYS} days"
            end

            super
          end

          def resolve(identifier:, timeframe:)
            count, last_recorded_at = with_cache(identifier, timeframe) do
              if queries_contributors?(identifier)
                contributor_count_data(timeframe)
              else
                ::Analytics::ValueStreamDashboard::Count
                  .aggregate_for_period(
                    namespace,
                    identifier.to_sym,
                    timeframe[:start],
                    timeframe[:end]
                  )
              end
            end

            return unless last_recorded_at

            {
              recorded_at: last_recorded_at,
              count: count,
              identifier: identifier
            }
          end

          private

          alias_method :namespace, :object

          def with_cache(identifier, timeframe, &block)
            return yield unless Feature.enabled?(:cache_value_stream_dashboard_counts, namespace)

            # Limited CH selects can return partial counts, so they must not share entries with unlimited ones.
            cache_key = ['value_stream_dashboard_counts', namespace.id, identifier, timeframe[:start].to_s,
              timeframe[:end].to_s, ::ClickHouse::QueryLimiting.rule.type]
            Rails.cache.fetch(cache_key, expires_in: CACHE_TTL, &block)
          end

          def queries_contributors?(identifier)
            identifier == Types::Analytics::ValueStreamDashboard::MetricEnum::CONTRIBUTOR_METRIC
          end

          def contributor_count_data(timeframe)
            service_response = ::Analytics::ValueStreamDashboard::ContributorCountService
              .new(
                namespace: namespace,
                current_user: current_user,
                from: timeframe[:start],
                to: timeframe[:end]
              ).execute

            if service_response.error?
              raise GraphQL::ExecutionError,
                service_response.message
            end

            # Since this is not an aggregated metric, we can return the current time for the last_record_at_value.
            [service_response.payload[:count], Time.current]
          end
        end
      end
    end
  end
end
