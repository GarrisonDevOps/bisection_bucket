# frozen_string_literal: true

module EE
  module Types
    module Boards
      module BoardIssueInputType
        extend ActiveSupport::Concern

        prepended do
          # NONE/ANY epic filter can not be negated
          argument :epic_wildcard_id, ::Types::EpicWildcardIdEnum,
            required: false,
            description: 'Filter by epic ID wildcard. Incompatible with epicId.'

          argument :include_subepics, GraphQL::Types::Boolean,
            required: false,
            description: 'Whether to include subepics when filtering issues by epicId.'

          argument :iteration_wildcard_id, ::Types::IterationWildcardIdEnum,
            required: false,
            description: 'Filter by iteration ID wildcard.'

          argument :iteration_cadence_id, [::Types::GlobalIDType[::Iterations::Cadence]],
            required: false,
            description: 'Filter by a list of iteration cadence IDs.'

          argument :weight_wildcard_id, ::Types::WeightWildcardIdEnum,
            required: false,
            description: 'Filter by weight ID wildcard. Incompatible with weight.'

          argument :health_status_filter, ::Types::HealthStatusFilterEnum,
            required: false,
            as: :health_status,
            description: 'Health status of the issue, "none" and "any" values are supported.'

          argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
            required: false,
            experiment: { milestone: '17.10' },
            description: 'Filter by custom fields.'

          argument :status, ::Types::WorkItems::Widgets::StatusFilterInputType,
            required: false,
            description: 'Filter by status.',
            experiment: { milestone: '18.0' }
        end
      end
    end
  end
end
