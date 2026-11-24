# frozen_string_literal: true

module Mutations
  module ApprovalProjectRules
    class Delete < BaseMutation
      graphql_name 'approvalProjectRuleDelete'

      authorize :delete_approval_rule
      authorize_granular_token permissions: :delete_approval_rule, boundary_argument: :id, boundary: :project,
        boundary_type: :project

      argument :id, ::Types::GlobalIDType[::ApprovalProjectRule],
        required: true,
        description: 'Global ID of the approval project rule to delete.'

      field :approval_rule, ::Types::BranchRules::ApprovalProjectRuleType,
        null: true,
        description: 'Deleted approval rule.'

      def resolve(id:)
        approval_rule = authorized_find!(id: id)

        result = ::ApprovalRules::ProjectRuleDestroyService.new(approval_rule, current_user).execute

        {
          approval_rule: (approval_rule if result.success?),
          errors: approval_rule.errors.full_messages
        }
      rescue Gitlab::Access::AccessDeniedError
        raise_resource_not_available_error!
      end
    end
  end
end
