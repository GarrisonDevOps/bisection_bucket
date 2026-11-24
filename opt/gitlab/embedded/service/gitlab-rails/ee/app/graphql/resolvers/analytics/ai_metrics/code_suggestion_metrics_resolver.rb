# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class CodeSuggestionMetricsResolver < BaseResolver
        include LooksAhead

        type ::Types::Analytics::AiMetrics::CodeSuggestionMetricsType, null: true

        argument :ide_names, [::GraphQL::Types::String],
          required: false,
          description: 'Filter code suggestion metrics by one or more IDE names.'

        argument :languages, [::GraphQL::Types::String],
          required: false,
          description: 'Filter code suggestion metrics by one or more languages.'

        def resolve_with_lookahead(**args)
          usage = ::Analytics::AiAnalytics::CodeSuggestionUsageService.new(
            current_user,
            namespace: context[:ai_metrics_namespace],
            from: context[:ai_metrics_params][:start_date],
            to: context[:ai_metrics_params][:end_date],
            fields: selected_fields,
            ide_names: args[:ide_names],
            languages: args[:languages]
          ).execute

          return unless usage.success?

          usage.payload
        end

        private

        def selected_fields
          lookahead.selections.map(&:name)
        end
      end
    end
  end
end
