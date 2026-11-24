# frozen_string_literal: true

module Types
  module Search
    module Blob
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization will be handled during fetching the results
      class ChunkType < BaseObject
        graphql_name 'SearchBlobChunk'
        description 'JSON structure of a matched chunk'

        field :lines, [::Types::Search::Blob::LineType], null: true, experiment: { milestone: '17.2' },
          description: 'Path of the file.'
        field :match_count_in_chunk, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Number of matches in the chunk.'
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
