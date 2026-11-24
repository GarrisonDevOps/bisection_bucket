# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module SavedViews
        module NegatedFilterInputType
          extend ActiveSupport::Concern

          prepended do
            argument :health_status_filter,
              [::Types::HealthStatusEnum],
              required: false,
              description: 'Filter values for not health status filter.'
            argument :weight,
              GraphQL::Types::String,
              required: false,
              description: 'Filter values for not weight filter.'
            argument :iteration_id,
              [::GraphQL::Types::ID],
              required: false,
              validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
              description: "Filter values for not iteration id filter. " \
                "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} IDs)."
            argument :iteration_wildcard_id,
              ::Types::IterationWildcardIdEnum,
              required: false,
              description: 'Filter value for not iteration wildcard id filter.'
            argument :custom_field,
              [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
              required: false,
              description: 'Filter value for not custom field filter.'

            validates mutually_exclusive: [:iteration_id, :iteration_wildcard_id]
          end
        end
      end
    end
  end
end
