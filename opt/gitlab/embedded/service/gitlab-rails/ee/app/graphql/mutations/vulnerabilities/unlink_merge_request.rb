# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class UnlinkMergeRequest < BaseMutation
      graphql_name 'VulnerabilityUnlinkMergeRequest'
      description 'Unlink a merge request from a vulnerability'

      authorize :admin_vulnerability_merge_request_link

      authorize_granular_token permissions: :delete_vulnerability_merge_request_link,
        boundary_argument: :vulnerability_id, boundary: :project, boundary_type: :project

      argument :vulnerability_id, ::Types::GlobalIDType[::Vulnerability],
        required: true, description: 'ID of the vulnerability.'

      argument :merge_request_id, ::Types::GlobalIDType[::MergeRequest],
        required: true, description: 'ID of the merge request.'

      field :vulnerability, Types::VulnerabilityType,
        null: true, description: 'Updated vulnerability.'

      def self.authorization_scopes
        [:api, :ai_workflows]
      end

      def resolve(vulnerability_id:, merge_request_id:)
        vulnerability = authorized_find!(id: vulnerability_id)
        merge_request = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(merge_request_id))

        unless can_read_merge_request?(merge_request)
          return { vulnerability: vulnerability,
                   errors: ['The merge request does not exist or you do not have permission to view it.'] }
        end

        merge_request_link = ::Vulnerabilities::MergeRequestLink
          .find_by_vulnerability_and_merge_request(vulnerability, merge_request)

        unless merge_request_link
          return { vulnerability: vulnerability, errors: ['Merge request is not linked to this vulnerability'] }
        end

        result = ::VulnerabilityMergeRequestLinks::DestroyService.new(
          project: vulnerability.project,
          current_user: current_user,
          params: {
            merge_request_link: merge_request_link
          }
        ).execute

        if result.success?
          { vulnerability: vulnerability, errors: [] }
        else
          { vulnerability: vulnerability, errors: result.payload[:errors] }
        end
      end

      def can_read_merge_request?(merge_request)
        merge_request.present? && Ability.allowed?(current_user, :read_merge_request, merge_request)
      end
    end
  end
end
