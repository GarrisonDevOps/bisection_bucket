# frozen_string_literal: true

module Mutations
  module Projects
    module BranchRules
      module SquashOptions
        class Create < BaseMutation
          graphql_name 'BranchRuleSquashOptionCreate'
          description 'Create a squash option for a branch rule'

          authorize :create_squash_option
          authorize_granular_token permissions: :create_squash_option,
            boundary_argument: :branch_rule_id, boundary: :project, boundary_type: :project

          argument :branch_rule_id, ::Types::GlobalIDType[::Projects::BranchRule],
            required: true,
            description: 'Global ID of the branch rule.'

          argument :squash_option, ::Types::Projects::BranchRules::SquashOptionSettingEnum,
            required: true,
            description: 'Squash option to set for the branch rule.'

          field :squash_option,
            type: ::Types::Projects::BranchRules::SquashOptionType,
            null: true,
            description: 'Created squash option after mutation.'

          def resolve(branch_rule_id:, **params)
            branch_rule = authorized_find!(id: branch_rule_id)

            service_response = ::BranchRules::SquashOptions::CreateService
              .new(branch_rule, user: current_user, params: params)
              .execute

            {
              squash_option: (service_response.payload if service_response.success?),
              errors: service_response.errors
            }
          end
        end
      end
    end
  end
end
