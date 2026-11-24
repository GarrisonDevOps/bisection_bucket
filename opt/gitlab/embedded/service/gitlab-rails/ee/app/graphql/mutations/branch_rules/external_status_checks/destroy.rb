# frozen_string_literal: true

module Mutations
  module BranchRules
    module ExternalStatusChecks
      class Destroy < BaseMutation
        graphql_name 'BranchRuleExternalStatusCheckDestroy'
        description 'Destroy an external status check from a branch rule'

        authorize :delete_external_status_check
        authorize_granular_token permissions: :delete_external_status_check,
          boundary_argument: :branch_rule_id, boundary: :project, boundary_type: :project

        argument :id, ::Types::GlobalIDType[::MergeRequests::ExternalStatusCheck],
          required: true,
          description: 'Global ID of the external status check to destroy.'

        argument :branch_rule_id, ::Types::GlobalIDType[::Projects::BranchRule],
          required: true,
          description: 'Global ID of the branch rule.'

        def resolve(branch_rule_id:, **params)
          branch_rule = authorized_find!(id: branch_rule_id)

          params[:id] = external_status_check_id(params[:id])

          response = ::BranchRules::ExternalStatusChecks::DestroyService
            .new(branch_rule, user: current_user, params: params)
            .execute

          if response.error? && (response.cause.access_denied? || response.cause.not_found?)
            raise_resource_not_available_error!
          end

          { errors: Array(response.payload[:errors]) }
        end

        private

        def external_status_check_id(external_status_check_id)
          ::GitlabSchema.parse_gid(external_status_check_id).model_id
        end
      end
    end
  end
end
