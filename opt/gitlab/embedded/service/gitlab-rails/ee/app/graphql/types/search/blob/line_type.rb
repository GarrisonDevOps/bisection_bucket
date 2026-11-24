# frozen_string_literal: true

module Types
  module Search
    module Blob
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization will be handled during fetching the results
      class LineType < BaseObject
        graphql_name 'SearchBlobLine'
        description 'JSON structure of each line in a matched chunk'

        field :highlights, [[GraphQL::Types::Int]], null: true,
          experiment: { milestone: '17.8' },
          description: 'Column numbers of the first and last highlighted characters on a line.'
        field :line_number, GraphQL::Types::Int, null: true, experiment: { milestone: '17.2' },
          description: 'Line number of the blob.'
        field :text, GraphQL::Types::String, null: true, experiment: { milestone: '17.2' },
          description: 'Text content of the blob.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
