# frozen_string_literal: true

module Types
  module ComplianceManagement
    module Projects
      class ComplianceViolationFilterInputType < BaseInputObject
        graphql_name 'ProjectComplianceViolationFilterInput'
        description 'Filters for project compliance violations.'

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: 'Project ID for which to filter compliance violations.',
          prepare: ->(id, _ctx) { id.model_id }

        argument :control_id,
          ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl],
          required: false,
          description: 'Control ID for which to filter compliance violations.',
          prepare: ->(id, _ctx) { id.model_id }

        argument :status, [::Types::ComplianceManagement::Projects::ComplianceViolationStatusEnum],
          required: false,
          description: 'Status of the project compliance violation.'

        argument :created_before, ::Types::DateType,
          required: false,
          description: 'Compliance violations created on or before the date (inclusive).'

        argument :created_after, ::Types::DateType,
          required: false,
          description: 'Compliance violations created on or after the date (inclusive).'
      end
    end
  end
end
