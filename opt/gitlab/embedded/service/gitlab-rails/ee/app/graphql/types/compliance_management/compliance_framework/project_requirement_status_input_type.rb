# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectRequirementStatusInputType < BaseInputObject
        graphql_name 'ProjectRequirementComplianceStatusInput'

        argument :requirement_id,
          ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirement],
          required: false,
          description: 'Filter compliance requirement statuses by compliance requirement.',
          prepare: ->(id, _ctx) { id.model_id }

        argument :framework_id, ::Types::GlobalIDType[::ComplianceManagement::Framework],
          required: false,
          description: 'Filter compliance requirement statuses by compliance framework.',
          prepare: ->(id, _ctx) { id.model_id }
      end
    end
  end
end
