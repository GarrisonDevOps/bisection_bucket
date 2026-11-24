# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module SavedViews
        module FilterInputType
          extend ActiveSupport::Concern

          prepended do
            argument :custom_field,
              [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
              required: false,
              validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
              description: "Filter value for custom field filter. " \
                "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} fields)."
            argument :health_status_filter,
              ::Types::HealthStatusFilterEnum,
              required: false,
              description: 'Filter value for health status filter.'
            argument :iteration_id,
              [::GraphQL::Types::ID],
              required: false,
              description: 'Filter value for iteration id filter.',
              validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } }
            argument :iteration_wildcard_id,
              ::Types::IterationWildcardIdEnum,
              required: false,
              description: 'Filter value for iteration wildcard id filter.'
            argument :status,
              ::Types::WorkItems::Widgets::StatusFilterInputType,
              required: false,
              description: 'Filter value for status filter.'
            argument :weight,
              GraphQL::Types::String,
              required: false,
              description: 'Filter value for weight filter.'
            argument :weight_wildcard_id,
              ::Types::WeightWildcardIdEnum,
              required: false,
              description: 'Filter value for weight wildcard id filter.'
            argument :iteration_cadence_id,
              [::Types::GlobalIDType[::Iterations::Cadence]],
              required: false,
              validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
              description: "Filter value for iteration cadence id filter. " \
                "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} IDs).",
              prepare: ->(iteration_cadence_ids, _ctx) {
                return unless iteration_cadence_ids.present?

                iteration_cadence_ids.map do |arg|
                  ::GitlabSchema.parse_gid(arg, expected_type: ::Iterations::Cadence).model_id
                end
              }

            validates mutually_exclusive: [:weight, :weight_wildcard_id]
            validates mutually_exclusive: [:iteration_id, :iteration_wildcard_id]
          end
        end
      end
    end
  end
end
