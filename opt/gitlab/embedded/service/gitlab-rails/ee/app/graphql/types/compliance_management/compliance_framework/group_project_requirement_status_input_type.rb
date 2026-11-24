# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class GroupProjectRequirementStatusInputType < ProjectRequirementStatusInputType
        graphql_name 'GroupProjectRequirementComplianceStatusInput'

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: 'Filter compliance requirement statuses by project.',
          prepare: ->(id, _ctx) { id.model_id }
      end
    end
  end
end
