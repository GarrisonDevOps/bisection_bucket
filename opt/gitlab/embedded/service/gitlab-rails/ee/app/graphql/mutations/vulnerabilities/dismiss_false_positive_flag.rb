# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class DismissFalsePositiveFlag < BaseMutation
      graphql_name 'VulnerabilityDismissFalsePositiveFlag'
      description 'Dismiss a vulnerability false positive flag'

      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :admin_vulnerability

      authorize_granular_token permissions: :update_vulnerability_flag,
        boundary_argument: :id, boundary: :project, boundary_type: :project

      field :vulnerability,
        ::Types::VulnerabilityType,
        null: true,
        description: 'Vulnerability after dismissing false positive flag.'

      argument :id,
        ::Types::GlobalIDType[::Vulnerability],
        required: true,
        description: 'ID of the vulnerability to dismiss false positive flag for.'

      def resolve(id:)
        vulnerability = authorized_find!(id: id)

        result = ::Vulnerabilities::Flags::DismissFalsePositiveService
          .new(current_user, vulnerability)
          .execute

        if result.success?
          {
            vulnerability: vulnerability,
            errors: []
          }
        else
          {
            vulnerability: nil,
            errors: [result.message]
          }
        end
      end
    end
  end
end
