# frozen_string_literal: true

module Types
  module Vulnerabilities
    class ArchivalInformationType < BaseObject # rubocop: disable Graphql/AuthorizeTypes -- Authorization is done in the parent type
      graphql_name 'VulnerabilityArchivalInformation'
      description 'Represents vulnerability archival information'

      field :about_to_be_archived, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether the vulnerability is about to be archived in the next month.'

      field :expected_to_be_archived_on, Types::DateType,
        null: true, description: 'Date when the vulnerability is expected to be archived.'
    end
  end
end
