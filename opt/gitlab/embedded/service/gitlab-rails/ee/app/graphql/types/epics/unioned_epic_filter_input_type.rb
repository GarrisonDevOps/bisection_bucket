# frozen_string_literal: true

module Types
  module Epics
    class UnionedEpicFilterInputType < BaseInputObject
      graphql_name 'UnionedEpicFilterInput'

      argument :label_name, [GraphQL::Types::String],
        required: false,
        description: 'Filters epics that have at least one of the given labels.',
        deprecated: { reason: 'Use labelNames instead', milestone: '16.6' }

      argument :label_names, [GraphQL::Types::String],
        required: false,
        description: 'Filters epics that have at least one of the given labels.'

      argument :author_username, [GraphQL::Types::String],
        required: false,
        description: 'Filters epics that are authored by one of the given users.',
        deprecated: { reason: 'Use authorUsernames instead', milestone: '16.6' }

      argument :author_usernames, [GraphQL::Types::String],
        required: false,
        description: 'Filters epics that are authored by one of the given users.'

      argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
        required: false,
        experiment: { milestone: '18.4' },
        description: 'Filter custom fields by one of the given values.'
    end
  end
end
