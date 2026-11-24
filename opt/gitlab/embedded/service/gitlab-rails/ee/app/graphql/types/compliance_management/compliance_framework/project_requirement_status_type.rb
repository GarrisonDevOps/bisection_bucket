# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      class ProjectRequirementStatusType < ::Types::BaseObject
        graphql_name 'ProjectComplianceRequirementStatus'
        description 'Compliance requirement status for a project.'

        authorize :read_compliance_adherence_report

        field :id, GraphQL::Types::ID,
          null: false, description: 'Compliance requirement status ID.'

        field :updated_at, Types::TimeType,
          null: false, description: 'Timestamp when the requirement status was last updated.'

        field :pass_count, GraphQL::Types::Int, null: false,
          description: 'Total no. of passed compliance controls for the requirement.'

        field :fail_count, GraphQL::Types::Int, null: false,
          description: 'Total no. of failed compliance controls for the requirement.'

        field :pending_count, GraphQL::Types::Int, null: false,
          description: 'Total no. of pending compliance controls for the requirement.'

        field :not_applicable_count, GraphQL::Types::Int, null: false,
          description: 'Total no. of not applicable compliance controls for the requirement.'

        field :project, ::Types::ProjectType,
          null: false, description: 'Project of the compliance status.'

        field :compliance_framework, ::Types::ComplianceManagement::ComplianceFrameworkType,
          null: false, description: 'Framework of the compliance status.'

        field :compliance_requirement, ::Types::ComplianceManagement::ComplianceRequirementType, # rubocop:disable GraphQL/ExtractType -- no need for reuse
          null: false, description: 'Requirement of the compliance status.'
      end
    end
  end
end
