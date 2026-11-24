# frozen_string_literal: true

module Types
  module Boards
    class BoardEpicInputType < BoardIssuableInputBaseType
      graphql_name 'EpicFilters'

      class NegatedEpicBoardIssueInputType < BoardIssuableInputBaseType
        # `authorUsername` (single) is inherited from the base type.
        # `authorUsernames` is additive so multi-author negation is supported
        # without changing the existing scalar argument's type. Both map to the
        # finder's `author_username`.
        argument :author_usernames, [GraphQL::Types::String],
          required: false,
          validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
          description: 'Filter by author usernames ' \
            "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} usernames)."

        argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
          required: false,
          experiment: { milestone: '18.4' },
          description: 'Filter by negated custom fields.'

        validates mutually_exclusive: [:author_username, :author_usernames]
      end

      argument :not, NegatedEpicBoardIssueInputType,
        required: false,
        description: 'Negated epic arguments.'

      argument :or, Types::Epics::UnionedEpicFilterInputType,
        required: false,
        description: 'List of arguments with inclusive OR.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search query for epic title or description.'

      argument :confidential, GraphQL::Types::Boolean,
        required: false,
        description: 'Filter by confidentiality.'

      argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
        required: false,
        experiment: { milestone: '17.10' },
        description: 'Filter by custom fields.'
    end
  end
end
