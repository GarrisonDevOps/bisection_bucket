# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class Confirm < BaseMutation
        graphql_name 'SecurityFindingConfirm'

        authorize :confirm_vulnerability

        authorize_granular_token permissions: :confirm_vulnerability,
          boundary_argument: :project_path, boundary_type: :project

        field :security_finding,
          ::Types::PipelineSecurityReportFindingType,
          null: true,
          description: 'Confirmed finding.'

        argument :project_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project the finding belongs to.'

        argument :uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the finding to be confirmed.'

        argument :comment,
          GraphQL::Types::String,
          required: false,
          validates: { length: { maximum: ::Vulnerabilities::StateTransition::COMMENT_MAX_LENGTH } },
          description: 'Comment that explains why the finding was confirmed (maximum 50,000 characters).'

        def resolve(project_path:, uuid:, comment: nil)
          security_finding = authorized_find!(project_path: project_path, uuid: uuid)
          result = ::Security::Findings::ConfirmService.new(
            user: current_user,
            security_finding: security_finding,
            comment: comment
          ).execute

          {
            security_finding: result.success? ? result.payload[:security_finding] : nil,
            errors: Array(result.message)
          }
        end

        private

        def find_object(project_path:, uuid:)
          project = ::Project.find_by_full_path(project_path)
          return unless project

          ::Security::Finding.by_project_id_and_uuid(project.id, nil, uuid).first
        end
      end
    end
  end
end
