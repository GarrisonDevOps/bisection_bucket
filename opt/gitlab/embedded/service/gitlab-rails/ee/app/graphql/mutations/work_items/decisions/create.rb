# frozen_string_literal: true

module Mutations
  module WorkItems
    module Decisions
      class Create < BaseMutation
        graphql_name 'WorkItemDecisionCreate'

        description 'Records a decision in the decision log of a work item.'

        authorize :update_work_item
        authorize_granular_token permissions: :update_work_item,
          boundaries: [
            { boundary_argument: :work_item_id, boundary: :resource_parent, boundary_type: :project },
            { boundary_argument: :work_item_id, boundary: :resource_parent, boundary_type: :group }
          ]

        argument :work_item_id,
          ::Types::GlobalIDType[::WorkItem],
          required: true,
          description: 'Global ID of the work item.'

        argument :question, GraphQL::Types::String,
          required: false,
          description: 'Question being decided. Required unless resolution is provided.'

        argument :title, GraphQL::Types::String,
          required: false,
          deprecated: { reason: 'Use `question`', milestone: '19.6' },
          description: 'Question being decided. Required unless resolution is provided.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Context of the decision.'

        argument :discussion_id, ::Types::GlobalIDType[::Discussion],
          required: false,
          # The model stores and validates the bare 40-char discussion SHA
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          description: 'Global ID of the originating discussion thread.'

        argument :source_link, GraphQL::Types::String,
          required: false,
          description: 'URL of the comment, discussion, or external resource that prompted the decision.'

        argument :resolution, ::Types::WorkItems::DecisionResolutionInputType,
          required: false,
          prepare: ->(input, _ctx) { input&.to_h },
          description: 'When present, records the decision as resolved at creation. ' \
            'Incompatible with options.'

        argument :options,
          [::Types::WorkItems::DecisionOptionInputType],
          required: false,
          description: 'Candidate options of the decision. ' \
            "Maximum of #{::WorkItems::Decision::MAX_OPTIONS_PER_DECISION} options. " \
            'Incompatible with resolution.',
          validates: { length: { maximum: ::WorkItems::Decision::MAX_OPTIONS_PER_DECISION } }

        validates mutually_exclusive: [:options, :resolution]
        validates mutually_exclusive: [:title, :question]
        validates at_least_one_of: [:question, :title, :resolution]

        field :decision, ::Types::WorkItems::DecisionType,
          null: true,
          description: 'Decision after mutation.'

        def resolve(work_item_id:, **args)
          args[:question] ||= args.delete(:title) if args.key?(:title)
          work_item = authorized_find!(id: work_item_id)

          # get_widget covers type registration, ai_workflows licensing, and
          # the decision_log feature flag
          raise_resource_not_available_error! unless work_item.get_widget(:decision_log)

          response = ::WorkItems::Decisions::CreateService.new(
            work_item: work_item,
            current_user: current_user,
            params: args
          ).execute

          {
            decision: response.success? ? response.payload[:decision] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
