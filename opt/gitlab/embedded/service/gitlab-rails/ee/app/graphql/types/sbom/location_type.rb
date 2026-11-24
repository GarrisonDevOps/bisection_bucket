# frozen_string_literal: true

module Types
  module Sbom
    # Location is a hash, and authorization checks are implemented
    # on the parent object.
    class LocationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes
      field :blob_path, GraphQL::Types::String,
        null: true, description: 'HTTP URI path to view the input file in GitLab.'

      field :path, GraphQL::Types::String,
        null: true, description: 'Path, relative to the root of the repository, of the file' \
                                 'which was analyzed to detect the dependency.'

      field :top_level, GraphQL::Types::Boolean,
        null: true, description: 'Is top level dependency.'

      field :ancestors, [Types::Sbom::AncestorType],
        null: true, description: 'Ancestors of the dependency.'
    end
  end
end
