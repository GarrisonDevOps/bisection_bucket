# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ComplianceRequirementInputType < BaseInputObject
      graphql_name 'ComplianceRequirementInput'

      argument :name,
        GraphQL::Types::String,
        required: false,
        description: 'New name for the compliance requirement.'

      argument :description,
        GraphQL::Types::String,
        required: false,
        description: 'New description for the compliance requirement.'

      argument :compliance_requirements_controls,
        [::Types::ComplianceManagement::ComplianceRequirementsControlInputType],
        required: false,
        description: 'Compliance controls of the compliance requirement.'
    end
  end
end
