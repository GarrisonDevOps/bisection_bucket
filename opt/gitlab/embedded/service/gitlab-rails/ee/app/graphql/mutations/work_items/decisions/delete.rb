# frozen_string_literal: true

module Mutations
  module WorkItems
    module Decisions
      class Delete < BaseMutation
        graphql_name 'WorkItemDecisionDelete'

        description 'Deletes an open decision from the decision log of a work item. ' \
          'Resolved or archived decisions cannot be deleted; archive resolved decisions instead.'

        authorize :update_work_item
        authorize_granular_token permissions: :update_work_item,
          boundaries: [
            { boundary_argument: :id, boundary: :resource_parent, boundary_type: :project },
            { boundary_argument: :id, boundary: :resource_parent, boundary_type: :group }
          ]

        argument :id,
          ::Types::GlobalIDType[::WorkItems::Decision],
          required: true,
          description: 'Global ID of the decision.'

        field :decision, ::Types::WorkItems::DecisionType,
          null: true,
          description: 'Deleted decision.'

        def resolve(id:)
          decision = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(id))
          raise_resource_not_available_error! unless decision

          authorize!(decision.work_item)

          # get_widget covers type registration, ai_workflows licensing, and
          # the decision_log feature flag
          raise_resource_not_available_error! unless decision.work_item.get_widget(:decision_log)

          response = ::WorkItems::Decisions::DeleteService.new(
            decision: decision,
            current_user: current_user
          ).execute

          {
            decision: response.success? ? response.payload[:decision] : nil,
            errors: response.errors
          }
        rescue ActiveRecord::RecordNotFound
          raise_resource_not_available_error!
        end
      end
    end
  end
end
