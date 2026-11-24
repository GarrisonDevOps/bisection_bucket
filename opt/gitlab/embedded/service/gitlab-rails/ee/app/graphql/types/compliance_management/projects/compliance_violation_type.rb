# frozen_string_literal: true

module Types
  module ComplianceManagement
    module Projects
      class ComplianceViolationType < ::Types::BaseObject
        graphql_name 'ProjectComplianceViolation'
        description 'Compliance violation for a project.'

        implements Types::Notes::NoteableInterface
        implements Types::TodoableInterface

        authorize :read_compliance_violations_report

        field :id, GraphQL::Types::ID,
          null: false, description: 'Compliance violation ID.'

        field :created_at, Types::TimeType,
          null: false, description: 'Timestamp when the violation was detected.'

        field :project, ::Types::ProjectType,
          null: false, description: 'Project of the compliance violation.'

        field :compliance_control, ::Types::ComplianceManagement::ComplianceRequirementsControlType,
          null: false, description: 'Compliance control of the violation.'

        field :status, ::Types::ComplianceManagement::Projects::ComplianceViolationStatusEnum,
          null: false, description: 'Compliance violation status of the project.'

        field :audit_event, Types::AuditEvents::AuditEventType,
          null: false, description: 'Audit event related to the violation.'

        field :issues, Types::IssueType.connection_type,
          null: true,
          description: 'Project issues linked to the violation.'

        def web_url
          Gitlab::UrlBuilder.build(object)
        end
      end
    end
  end
end
