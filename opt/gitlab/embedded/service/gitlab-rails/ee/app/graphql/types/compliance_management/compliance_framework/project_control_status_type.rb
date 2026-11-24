# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectControlStatusType < ::Types::BaseObject
        graphql_name 'ProjectComplianceControlStatusType'
        description 'Compliance control status for a project.'

        authorize :read_compliance_adherence_report

        field :id, GraphQL::Types::ID,
          null: false, description: 'Compliance control status ID.'

        field :updated_at, Types::TimeType,
          null: false, description: 'Timestamp when the control status was last updated.'

        field :status, ProjectControlStatusEnum,
          null: false, description: 'Compliance status of the project for the control.'

        field :compliance_requirements_control, ::Types::ComplianceManagement::ComplianceRequirementsControlType,
          null: false, description: 'Control of the compliance status.'
      end
    end
  end
end
