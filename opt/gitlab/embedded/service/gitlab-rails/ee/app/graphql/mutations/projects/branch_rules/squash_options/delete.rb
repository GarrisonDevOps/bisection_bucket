# frozen_string_literal: true

module Mutations
  module Projects
    module BranchRules
      module SquashOptions
        class Delete < BaseMutation
          graphql_name 'BranchRuleSquashOptionDelete'
          description 'Delete a squash option for a branch rule'

          authorize :delete_squash_option
          authorize_granular_token permissions: :delete_squash_option,
            boundary_argument: :branch_rule_id, boundary: :project, boundary_type: :project

          argument :branch_rule_id, ::Types::GlobalIDType[::Projects::BranchRule],
            required: true,
            description: 'Global ID of the branch rule.'

          def resolve(branch_rule_id:)
            branch_rule = authorized_find!(id: branch_rule_id)

            service_response = ::BranchRules::SquashOptions::DestroyService
              .new(branch_rule, user: current_user)
              .execute

            { errors: service_response.errors }
          end
        end
      end
    end
  end
end
