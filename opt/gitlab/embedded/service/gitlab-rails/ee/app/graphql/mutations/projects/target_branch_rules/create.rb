# frozen_string_literal: true

module Mutations
  module Projects
    module TargetBranchRules
      class Create < BaseMutation
        graphql_name 'ProjectTargetBranchRuleCreate'

        authorize :admin_target_branch_rule
        authorize_granular_token permissions: :create_target_branch_rule,
          boundary_argument: :project_id, boundary_type: :project

        field :target_branch_rule, ::Types::Projects::TargetBranchRuleType,
          null: true,
          description: 'Target branch rule after mutation.'

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'Project ID for the target branch rule.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: "Name for the target branch rule."

        argument :target_branch, GraphQL::Types::String,
          required: true,
          description: "Target branch for the target branch rule."

        def resolve(project_id:, name:, target_branch:)
          project = authorized_find!(id: project_id)

          result = ::TargetBranchRules::CreateService
            .new(project, current_user, { name: name, target_branch: target_branch })
            .execute

          if result[:status] == :success
            {
              target_branch_rule: result[:payload][:target_branch_rule],
              errors: []
            }
          else
            {
              target_branch_rule: nil,
              errors: result[:message]
            }
          end
        end
      end
    end
  end
end
