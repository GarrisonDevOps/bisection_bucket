# frozen_string_literal: true

module Mutations
  module BranchRules
    module ExternalStatusChecks
      class Update < BaseMutation
        graphql_name 'BranchRuleExternalStatusCheckUpdate'
        description 'Update an external status check from a branch rule'

        authorize :update_external_status_check
        authorize_granular_token permissions: :update_external_status_check,
          boundary_argument: :branch_rule_id, boundary: :project, boundary_type: :project

        argument :id, ::Types::GlobalIDType[::MergeRequests::ExternalStatusCheck],
          required: true,
          description: 'Global ID of the external status check to update.'

        argument :branch_rule_id, ::Types::GlobalIDType[::Projects::BranchRule],
          required: true,
          description: 'Global ID of the branch rule.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the external status check.'

        argument :external_url, GraphQL::Types::String,
          required: true,
          description: 'External URL of the external status check.'

        argument :shared_secret, GraphQL::Types::String,
          required: false,
          description: 'HMAC shared secret for authenticating external status check requests.'

        field :external_status_check,
          type: ::Types::BranchRules::ExternalStatusCheckType,
          null: true,
          description: 'Updated external status check after mutation.'

        def resolve(branch_rule_id:, **params)
          branch_rule = authorized_find!(id: branch_rule_id)

          params[:id] = external_status_check_id(params[:id])

          response = ::BranchRules::ExternalStatusChecks::UpdateService
            .new(branch_rule, user: current_user, params: params)
            .execute

          if response.error? && (response.cause.access_denied? || response.cause.not_found?)
            raise_resource_not_available_error!
          end

          external_status_check = response.payload[:external_status_check]

          {
            external_status_check: (external_status_check if response.success?),
            errors: Array(response.payload[:errors])
          }
        end

        private

        def external_status_check_id(id)
          ::GitlabSchema.parse_gid(id).model_id
        end
      end
    end
  end
end
