# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dora
      class PerformanceScoresCountResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include LooksAhead

        authorize :read_dora4_analytics
        authorizes_object!
        type [::Types::Analytics::Dora::PerformanceScoreCountType], null: true

        argument :project_filters, ::Types::Analytics::Dora::ProjectFilterInputType,
          required: false,
          description: 'Filter DORA metric results by project attributes.'

        alias_method :group, :object

        def resolve_with_lookahead(**args)
          # return only the metric names if that's all that's requested.
          # Not sure why someone would query that, but it's GraphQL so :shrug:
          return only_metric_names if no_counts_selected?

          filter_params = args[:project_filters].to_h

          service = ::Dora::AggregateScoresService.new(container: group,
            params: filter_params, current_user: current_user)

          result = service.execute

          raise Gitlab::Graphql::Errors::ArgumentError, result[:message] unless result[:status] == :success

          context[:authorized_projects_count] = result[:authorized_projects_count]
          context[:projects_without_dora_data_count] = result[:projects_without_dora_data_count]

          result.payload[:aggregations]
        end

        private

        def only_metric_names
          ::Dora::DailyMetrics::AVAILABLE_METRICS.map { |key| { metric_name: key } }
        end

        def no_counts_selected?
          [:lowProjectsCount, :mediumProjectsCount, :highProjectsCount, :noDataProjectsCount]
            .none? { |name| node_selection&.selects?(name) }
        end
      end
    end
  end
end
