# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class NamespaceMetricsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include LooksAhead

        type ::Types::Analytics::AiMetrics::NamespaceMetricsType, null: true

        authorizes_object!
        authorize :read_pro_ai_analytics

        argument :start_date, Types::DateType,
          required: false,
          description: 'Date range to start from. Default is the beginning of current month.'

        argument :end_date, Types::DateType,
          required: false,
          description: 'Date range to end at. Default is the end of current month.'

        def ready?(**args)
          validate_params!(args)

          super
        end

        def resolve_with_lookahead(**args)
          params = params_with_defaults(args)

          # Creates parameters context to be used in resolvers coming later in the chain.
          set_context(params)

          usage = ::Analytics::AiAnalytics::AiMetricsService.new(
            current_user,
            namespace: namespace,
            from: params[:start_date],
            to: params[:end_date],
            fields: lookahead.selections.map(&:name)
          ).execute

          return unless usage.success?

          usage.payload
        end

        private

        def set_context(params)
          context[:ai_metrics_params] = params
          context[:ai_metrics_namespace] = namespace
        end

        def validate_params!(args)
          params = params_with_defaults(args)

          if params[:start_date].present? && params[:end_date].present? && params[:start_date] > params[:end_date]
            raise Gitlab::Graphql::Errors::ArgumentError, "start date cannot be after end date"
          end

          return unless params[:start_date] < params[:end_date] - 1.year

          raise Gitlab::Graphql::Errors::ArgumentError, 'maximum date range is 1 year'
        end

        def params_with_defaults(args)
          { start_date: Time.current.beginning_of_month, end_date: Time.current.end_of_month }.merge(args)
        end

        def namespace
          object.respond_to?(:project_namespace) ? object.project_namespace : object
        end
      end
    end
  end
end
