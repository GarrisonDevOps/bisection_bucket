# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class RefreshSecurityFindingTokenStatus < BaseMutation
        graphql_name 'RefreshSecurityFindingTokenStatus'

        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorize :update_secret_detection_validity_check_status

        field :finding_token_status,
          ::Types::Security::FindingTokenStatusType,
          null: true,
          description: 'Updated token status record for the given Security::Finding.'

        argument :security_finding_uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the Security::Finding whose token status should be refreshed (MR context).'

        def resolve(security_finding_uuid:)
          security_finding = ::Security::Finding.find_by_uuid(security_finding_uuid)
          raise_resource_not_available_error! unless security_finding

          project = security_finding.project
          authorize!(project)

          raise_resource_not_available_error! unless project&.security_setting&.validity_checks_enabled?

          ::Security::SecretDetection::UpdateTokenStatusService
            .new
            .execute_for_security_finding(security_finding.id)

          token_status = security_finding.reset.token_status
          return { errors: ['Token status not found.'], finding_token_status: nil } unless token_status

          { errors: [], finding_token_status: token_status }
        end
      end
    end
  end
end
