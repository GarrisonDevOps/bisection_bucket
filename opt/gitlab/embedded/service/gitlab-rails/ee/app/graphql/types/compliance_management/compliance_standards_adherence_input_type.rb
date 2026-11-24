# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ComplianceStandardsAdherenceInputType < BaseInputObject
      graphql_name 'ComplianceStandardsAdherenceInput'
      description 'Arguments for filtering compliance standards adherences'

      argument :project_ids, [::Types::GlobalIDType[::Project]],
        required: false,
        description: 'Global ID of the project.',
        prepare: ->(ids, _ctx) { ids.map(&:model_id) }

      argument :check_name,
        ::GraphQL::Types::String,
        required: false,
        description: 'Name of the check for the compliance standard.'

      argument :standard_name,
        ::GraphQL::Types::String,
        required: false,
        description: 'Name of the compliance standard.'
    end
  end
end
