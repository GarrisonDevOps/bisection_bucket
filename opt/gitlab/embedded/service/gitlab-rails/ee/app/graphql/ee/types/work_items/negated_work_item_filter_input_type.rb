# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module NegatedWorkItemFilterInputType
        extend ActiveSupport::Concern

        prepended do
          argument :health_status_filter, [::Types::HealthStatusEnum],
            required: false,
            description: 'Health status not applied to the work items.
                    Includes work items where health status is not set.'
          argument :weight, GraphQL::Types::String,
            required: false,
            description: 'Weight not applied to the work items.'
          argument :iteration_id, [::GraphQL::Types::ID],
            required: false,
            validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
            description: "List of iteration Global IDs not applied to the work items " \
              "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} IDs)."
          argument :iteration_wildcard_id, ::Types::IterationWildcardIdEnum,
            required: false,
            description: 'Filter by negated iteration ID wildcard.'

          argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
            required: false,
            experiment: { milestone: '18.4' },
            description: 'Filter by negated custom fields.'

          validates mutually_exclusive: [:iteration_id, :iteration_wildcard_id]
        end
      end
    end
  end
end
