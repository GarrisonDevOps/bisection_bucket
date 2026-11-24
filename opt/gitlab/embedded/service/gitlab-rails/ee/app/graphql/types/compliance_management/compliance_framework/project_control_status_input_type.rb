# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectControlStatusInputType < BaseInputObject
        graphql_name 'ProjectComplianceControlStatusInput'

        argument :compliance_requirement_id,
          ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirement],
          required: false,
          description: 'Compliance requirement id of the statuses.',
          prepare: ->(id, _ctx) { id.model_id }
      end
    end
  end
end
