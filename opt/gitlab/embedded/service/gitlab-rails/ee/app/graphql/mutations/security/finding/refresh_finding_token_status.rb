# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class RefreshFindingTokenStatus < BaseMutation
        # We will deprecate this mutation in 18.3
        # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200878#note_2694064620

        graphql_name 'RefreshFindingTokenStatus'

        include Gitlab::Graphql::Authorize::AuthorizeResource
        include Gitlab::InternalEventsTracking

        authorize :update_secret_detection_validity_check_status

        authorize_granular_token permissions: :update_finding_token_status,
          boundary_argument: :vulnerability_id, boundary: :project, boundary_type: :project

        field :finding_token_status,
          Types::Vulnerabilities::FindingTokenStatusType,
          null: true,
          description: 'Updated token status record for the given finding.'

        argument :vulnerability_id,
          ::Types::GlobalIDType[::Vulnerability],
          required: true,
          description: 'Global ID of the Vulnerability whose token status should be refreshed.'

        def resolve(vulnerability_id:)
          vuln = authorized_find!(id: vulnerability_id)

          raise_resource_not_available_error! unless vuln.project&.security_setting&.validity_checks_enabled?

          finding = vuln.finding
          return raise_resource_not_available_error! unless finding

          track_internal_event(
            'call_api_refresh_token_status',
            project: vuln.project
          )

          ::Security::SecretDetection::UpdateTokenStatusService
            .new
            .execute_for_vulnerability_finding(finding.id)

          token_status = finding.reset.finding_token_status
          return { errors: ["Token status not found."], finding_token_status: nil } unless token_status

          { errors: [], finding_token_status: token_status }
        end
      end
    end
  end
end
