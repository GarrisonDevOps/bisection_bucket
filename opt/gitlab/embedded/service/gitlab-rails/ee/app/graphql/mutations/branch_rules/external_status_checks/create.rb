# frozen_string_literal: true

module Mutations
  module BranchRules
    module ExternalStatusChecks
      class Create < BaseMutation
        graphql_name 'BranchRuleExternalStatusCheckCreate'
        description 'Create a new external status check from a branch rule'

        authorize :create_external_status_check
        authorize_granular_token permissions: :create_external_status_check,
          boundary_argument: :branch_rule_id, boundary: :project, boundary_type: :project

        argument :branch_rule_id, ::Types::GlobalIDType[::Projects::BranchRule],
          required: true,
          description: 'Global ID of the branch rule to update.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the external status check.'

        argument :external_url, GraphQL::Types::String,
          required: true,
          description: 'URL of external status check resource.'

        argument :shared_secret, GraphQL::Types::String,
          required: false,
          description: 'HMAC shared secret for authenticating external status check requests.'

        field :external_status_check,
          type: ::Types::BranchRules::ExternalStatusCheckType,
          null: true,
          description: 'New status check after mutation.'

        def resolve(branch_rule_id:, **params)
          branch_rule = authorized_find!(id: branch_rule_id)

          response = ::BranchRules::ExternalStatusChecks::CreateService
            .new(branch_rule, user: current_user, params: params)
            .execute

          if response.error? && (response.cause.access_denied? || response.cause.not_found?)
            raise_resource_not_available_error!
          end

          status_check = response.payload[:external_status_check]

          {
            external_status_check: (status_check if response.success?),
            errors: Array(response.payload[:errors])
          }
        end
      end
    end
  end
end
