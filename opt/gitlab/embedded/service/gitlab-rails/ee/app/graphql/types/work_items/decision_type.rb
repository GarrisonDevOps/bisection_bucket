# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop:disable Graphql/AuthorizeTypes -- authorized through the parent work item widget
    class DecisionType < BaseObject
      graphql_name 'WorkItemDecision'
      description 'Represents a decision recorded in the decision log of a work item.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, ::Types::GlobalIDType[::WorkItems::Decision],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the decision.'

      field :question, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Question being decided. May be absent for decisions recorded as already resolved at creation.'

      field :title, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Question being decided. Deprecated, use question instead. ' \
          'May be absent for decisions recorded as already resolved at creation.'

      field :description, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Context of the decision.'

      field :resolution_rationale, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Reasoning given when the decision was resolved.'

      field :resolved_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp when the decision was resolved.'

      field :archived_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Timestamp when the decision was archived.'

      field :state, ::Types::WorkItems::DecisionStateEnum,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'State of the decision.'

      field :note_url, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'URL of the comment that resolved the decision.'

      field :discussion_id, ::Types::GlobalIDType[::Discussion],
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the originating discussion thread.'

      field :source_link, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'URL of the comment, discussion, or external resource that prompted the decision. ' \
          'Present only on manually created decisions.'

      field :resolving_note_id, ::Types::GlobalIDType[::Note],
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the comment that resolved the decision.'

      field :author, ::Types::UserType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'User who raised the decision.'

      field :resolved_by, ::Types::UserType, # rubocop:disable GraphQL/ExtractType -- flat fields match the FE widget contract
        null: true,
        experiment: { milestone: '19.4' },
        description: 'User who resolved the decision.'

      field :options, ::Types::WorkItems::DecisionOptionType.connection_type,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Candidate options of the decision.'

      def author
        # author_id is nullable (SET NULL on user deletion)
        return unless object.author_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object.author_id).find
      end

      def resolved_by
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object.resolved_by_id).find if object.resolved_by_id
      end

      # Stored as the bare 40-char SHA; wrapped as a GID to match Discussion.id
      def discussion_id
        return unless object.discussion_id

        ::Gitlab::GlobalId.build(model_name: 'Discussion', id: object.discussion_id)
      end

      # Built from the FK so the note is never loaded just for its ID
      def resolving_note_id
        return unless object.resolving_note_id

        ::Gitlab::GlobalId.build(model_name: 'Note', id: object.resolving_note_id)
      end

      # Built without loading the note: the SET NULL FK guarantees it exists,
      # and ResolveService guarantees it belongs to this work item
      def note_url
        return unless object.resolving_note_id

        ::Gitlab::UrlBuilder.build(object.work_item, anchor: "note_#{object.resolving_note_id}")
      end

      # Materialized so the connection reuses the preloaded association
      # instead of issuing a paginated query per decision
      def options
        object.options.to_a
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
