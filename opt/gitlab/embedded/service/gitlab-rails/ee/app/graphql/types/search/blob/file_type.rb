# frozen_string_literal: true

module Types
  module Search
    module Blob
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization will be handled during fetching the results
      class FileType < BaseObject
        graphql_name 'SearchBlobFileType'
        description 'JSON structure of a file with matches'

        field :blame_url, GraphQL::Types::String, null: true, experiment: { milestone: '17.2' },
          description: 'Blame URL of the file.'

        field :chunks, [::Types::Search::Blob::ChunkType], null: true, experiment: { milestone: '17.2' },
          description: 'Maximum matches per file.'

        field :file_url, GraphQL::Types::String, null: true, experiment: { milestone: '17.2' },
          description: 'URL of the file.'

        field :language, GraphQL::Types::String, null: true, experiment: { milestone: '17.8' },
          description: 'Language of the file.'

        # rubocop:disable GraphQL/ExtractType -- no need to create an extra field just for two integers field
        field :match_count_total, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Total number of matches per file.'

        field :match_count, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: "Matches per file up to a max of #{::Search::Zoekt::MultiMatch::MAX_CHUNKS_PER_FILE} chunks. \
            Default is #{::Search::Zoekt::MultiMatch::DEFAULT_REQUESTED_CHUNK_SIZE}"
        # rubocop:enable GraphQL/ExtractType

        field :path, GraphQL::Types::String, null: true, experiment: { milestone: '17.2' },
          description: 'Path of the file.'

        field :project_path, GraphQL::Types::String, null: true, experiment: { milestone: '17.2' },
          description: 'Full path of the project.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
