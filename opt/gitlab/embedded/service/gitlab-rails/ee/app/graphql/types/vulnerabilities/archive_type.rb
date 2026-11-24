# frozen_string_literal: true

module Types
  module Vulnerabilities
    class ArchiveType < BaseObject # rubocop: disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'VulnerabilityArchive'
      description 'Represents a vulnerability archive'

      field :year, GraphQL::Types::Int,
        null: false, description: 'Year of the archive.'

      field :month, GraphQL::Types::Int,
        null: false, description: 'Month of the archive, represented as a number from 1 (January) to 12 (December).'

      field :archived_records_count, GraphQL::Types::Int,
        null: false, description: 'Number of records the archive contains.'
    end
  end
end
