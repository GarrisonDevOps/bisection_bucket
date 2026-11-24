# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop:disable Graphql/AuthorizeTypes -- authorized through the parent work item widget
    class AgentPlanQuestionType < BaseObject
      graphql_name 'WorkItemAgentPlanQuestion'
      description 'Represents a question a workplan flow asked on a work item.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :note_id, ::Types::GlobalIDType[::Note],
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        experiment: { milestone: '19.5' },
        description: 'Global ID of the comment that asked the question.'

      field :discussion_id, ::Types::GlobalIDType[::Discussion],
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        experiment: { milestone: '19.5' },
        description: 'Global ID of the thread the question was asked in.'

      field :answered, GraphQL::Types::Boolean,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        experiment: { milestone: '19.5' },
        description: 'Indicates the thread the question was asked in is resolved.'

      # The note's own GID, subclass and all, so it compares equal to the `id` the same
      # note carries in a notes query.
      def note_id
        object.note.to_global_id
      end

      # Stored as the bare 40-char SHA; wrapped as a GID to match Discussion.id
      def discussion_id
        ::Gitlab::GlobalId.build(model_name: 'Discussion', id: object.note.discussion_id)
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
