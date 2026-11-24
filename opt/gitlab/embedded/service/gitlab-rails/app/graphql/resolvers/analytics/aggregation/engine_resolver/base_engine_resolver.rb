# frozen_string_literal: true

module Resolvers
  module Analytics
    module Aggregation
      module EngineResolver
        class BaseEngineResolver < BaseResolver # rubocop:disable Graphql/ResolverType -- type declared in subclasses
          include ::Analytics::Aggregation::ResolvesAggregationSources

          class << self
            attr_accessor :engine
          end

          class_attribute :resource_ability

          MAX_DATE_RANGE_SPAN = 366.days
          MAX_DIMENSIONS = 10
          MAX_METRICS = 20

          argument :descendants_scope, ::Types::Analytics::Aggregation::ScopeInputType,
            required: false,
            description: 'Child groups and projects to aggregate data for. Not supported at project level. ' \
              'If omitted at group level, the whole group is aggregated. If omitted at organization level, ' \
              'organization owners and administrators on GitLab Self-Managed and GitLab Dedicated aggregate ' \
              'the whole organization. Other users aggregate all top-level groups where they can read the ' \
              "analytics, at most #{MAX_SOURCES} groups."

          def resolve(**arguments)
            authorize!(object) if self.class.authorization.any?

            non_metric_filters = engine_class.filters.reject(&:metric?)
            filters = ::Gitlab::Database::Aggregation::Graphql::Adapter
              .arguments_to_filters(non_metric_filters, arguments)
            request = ::Gitlab::Database::Aggregation::Request.new(filters: filters, metrics: [])

            {
              engine: engine_class.new(context: engine_context(arguments)),
              request: request,
              validate_request: method(:validate_request!)
            }
          end

          private

          def engine_class
            self.class.engine
          end

          # Overrides must call `super` to keep the default limits.
          def validate_request!(engine_request)
            return unless Feature.enabled?(:aggregation_engine_request_limits, request_limits_actor)

            validate_date_range!(engine_request)
            validate_parts_count!(engine_request)
          end

          def request_limits_actor
            return object unless object.respond_to?(:root_ancestor)

            object.root_ancestor || object
          end

          def validate_date_range!(engine_request)
            date_filters = engine_class.filters.select { |filter| date_range_filter?(filter) }
            return if date_filters.empty?

            identifiers = date_filters.map(&:identifier)
            bounded = engine_request.filters.filter_map do |config|
              range = config[:values]
              next unless identifiers.include?(config[:identifier]) && range.is_a?(Range) && range.begin

              [config[:identifier], range.begin, range.end || Time.current]
            end

            if bounded.empty?
              arguments = identifiers.map { |identifier| "#{graphql_name_for(identifier)}From" }

              raise ::Gitlab::Graphql::Errors::ArgumentError,
                "a date range start is required: set #{arguments.join(' or ')}"
            end

            identifier, _start, _finish = bounded.detect { |_, start, finish| finish > start + MAX_DATE_RANGE_SPAN }
            return unless identifier

            raise ::Gitlab::Graphql::Errors::ArgumentError,
              "the #{graphql_name_for(identifier)} date range may not span more than " \
                "#{MAX_DATE_RANGE_SPAN.in_days.to_i} days"
          end

          def validate_parts_count!(engine_request)
            if engine_request.dimensions.size > MAX_DIMENSIONS
              raise ::Gitlab::Graphql::Errors::ArgumentError,
                "too many dimensions requested: #{engine_request.dimensions.size} of a maximum of #{MAX_DIMENSIONS}"
            end

            return unless engine_request.metrics.size > MAX_METRICS

            raise ::Gitlab::Graphql::Errors::ArgumentError,
              "too many metrics requested: #{engine_request.metrics.size} of a maximum of #{MAX_METRICS}"
          end

          def date_range_filter?(filter)
            filter.is_a?(::Gitlab::Database::Aggregation::ClickHouse::RangeFilter) &&
              %i[date datetime].include?(filter.type.to_sym)
          end

          def graphql_name_for(identifier)
            identifier.to_s.camelize(:lower)
          end

          def engine_context(arguments)
            sources = aggregation_sources(arguments)

            {
              scope: engine_class.prepare_base_aggregation_scope(sources),
              current_user: current_user,
              authorization_resources: sources
            }
          end
        end
      end
    end
  end
end
