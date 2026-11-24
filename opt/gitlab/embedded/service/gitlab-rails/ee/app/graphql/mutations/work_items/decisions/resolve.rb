# frozen_string_literal: true

module Mutations
  module WorkItems
    module Decisions
      class Resolve < BaseMutation
        graphql_name 'WorkItemDecisionResolve'

        description 'Resolves a decision in the decision log of a work item.'

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

        argument :resolution_rationale, GraphQL::Types::String,
          required: false,
          description: 'Reasoning for the resolution.'

        argument :selected_option_ids,
          [::Types::GlobalIDType[::WorkItems::DecisionOption]],
          required: false,
          description: 'Global IDs of the selected options. ' \
            "Maximum of #{::WorkItems::Decision::MAX_OPTIONS_PER_DECISION} options.",
          validates: { length: { maximum: ::WorkItems::Decision::MAX_OPTIONS_PER_DECISION } }

        argument :resolving_note_id,
          ::Types::GlobalIDType[::Note],
          required: false,
          description: 'Global ID of the comment that resolved the decision.'

        argument :selected_option_content, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'Content of a custom option, added as the only selected option of the decision ' \
            'while every existing option is deselected. Incompatible with selectedOptionIds.'

        validates mutually_exclusive: [:selected_option_ids, :selected_option_content]

        field :decision, ::Types::WorkItems::DecisionType,
          null: true,
          description: 'Decision after mutation.'

        def resolve(id:, **args)
          decision = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(id))
          raise_resource_not_available_error! unless decision

          authorize!(decision.work_item)

          # get_widget covers type registration, ai_workflows licensing, and
          # the decision_log feature flag
          raise_resource_not_available_error! unless decision.work_item.get_widget(:decision_log)

          response = ::WorkItems::Decisions::ResolveService.new(
            decision: decision,
            current_user: current_user,
            params: resolve_params(args)
          ).execute

          {
            decision: response.success? ? response.payload[:decision] : decision.reset,
            errors: response.errors
          }
        rescue ActiveRecord::RecordNotFound
          raise_resource_not_available_error!
        end

        private

        def resolve_params(args)
          {
            resolution_rationale: args[:resolution_rationale],
            selected_option_ids: Array(args[:selected_option_ids]).map(&:model_id),
            selected_option_content: args[:selected_option_content],
            resolving_note: args[:resolving_note_id] &&
              ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(args[:resolving_note_id]))
          }
        end
      end
    end
  end
end
