# frozen_string_literal: true

module Mutations
  module WorkItems
    module Decisions
      class Update < BaseMutation
        graphql_name 'WorkItemDecisionUpdate'

        description 'Updates a decision in the decision log of a work item.'

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

        argument :question, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'Question being decided.'

        argument :title, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          deprecated: { reason: 'Use `question`', milestone: '19.6' },
          description: 'Question being decided.'

        argument :description, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'Context of the decision.'

        argument :resolution_rationale, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'Reasoning for the resolution. Can only be updated on resolved decisions.'

        argument :resolved_by_id, ::Types::GlobalIDType[::User],
          required: false,
          validates: { allow_blank: false },
          prepare: ->(global_id, _ctx) { global_id.model_id },
          description: 'Global ID of the user who resolved the decision. Can only be updated on resolved decisions.'

        argument :resolving_note_id, ::Types::GlobalIDType[::Note],
          required: false,
          validates: { allow_blank: false },
          prepare: ->(global_id, _ctx) { global_id.model_id },
          description: 'Global ID of the comment that resolved the decision. Can only be updated on resolved decisions.'

        argument :discussion_id, ::Types::GlobalIDType[::Discussion],
          required: false,
          validates: { allow_blank: false },
          # The model stores and validates the bare 40-char discussion SHA
          prepare: ->(global_id, _ctx) { global_id.model_id },
          description: 'Global ID of the originating discussion thread.'

        argument :source_link, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'URL of the comment, discussion, or external resource that prompted the decision.'

        argument :options, [::Types::WorkItems::DecisionOptionUpdateInputType],
          required: false,
          description: 'Existing options of the decision to update. ' \
            "Maximum of #{::WorkItems::Decision::MAX_OPTIONS_WITH_WRITE_IN} options.",
          validates: { length: { maximum: ::WorkItems::Decision::MAX_OPTIONS_WITH_WRITE_IN } }

        argument :selected_option_content, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          description: 'Content of the selected option. Unless exactly one option is selected, a new selected ' \
            'option with this content is added and any selected options are deselected. ' \
            'Can only be updated on resolved decisions.'

        validates at_least_one_of: [
          :question, :title, :description, :resolution_rationale, :discussion_id, :source_link,
          :resolved_by_id, :resolving_note_id, :options, :selected_option_content
        ]
        validates mutually_exclusive: [:title, :question]
        validates mutually_exclusive: [:options, :selected_option_content]

        field :decision, ::Types::WorkItems::DecisionType,
          null: true,
          description: 'Decision after mutation.'

        def resolve(id:, **args)
          args[:question] ||= args.delete(:title) if args.key?(:title)
          decision = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(id))
          raise_resource_not_available_error! unless decision

          authorize!(decision.work_item)

          # get_widget covers type registration, ai_workflows licensing, and
          # the decision_log feature flag
          raise_resource_not_available_error! unless decision.work_item.get_widget(:decision_log)

          response = ::WorkItems::Decisions::UpdateService.new(
            decision: decision,
            current_user: current_user,
            params: args
          ).execute

          {
            decision: response.success? ? response.payload[:decision] : decision.reset,
            errors: response.errors
          }
        rescue ActiveRecord::RecordNotFound
          raise_resource_not_available_error!
        end
      end
    end
  end
end
