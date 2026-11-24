# frozen_string_literal: true

module Types
  module Search
    module Blob
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization will be handled during fetching the results
      class BlobSearchType < BaseObject
        graphql_name 'BlobSearch'
        description 'Full JSON structure of multi-match results in a single file'

        field :duration_s, ::GraphQL::Types::Float, null: true, experiment: { milestone: '18.0' },
          description: 'Duration of the request in seconds.'
        field :file_count, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Total number of files with matches.'
        field :files, [::Types::Search::Blob::FileType], null: true, experiment: { milestone: '17.2' },
          description: 'List of files with matches.'
        field :match_count, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Total number of matches.'
        field :per_page, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Total number of files per page.'
        # rubocop:disable GraphQL/ExtractType -- no need to create an extra field just for two integers field
        field :search_level, ::Types::Search::SearchLevelEnum, null: true, experiment: { milestone: '17.2' },
          description: 'Level of search performed.'
        field :search_type, ::Types::Search::SearchTypeEnum, null: true, experiment: { milestone: '17.2' },
          description: 'Type of search performed.'
        # rubocop:enable GraphQL/ExtractType
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
