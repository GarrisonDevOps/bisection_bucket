# frozen_string_literal: true

module Types
  module Sbom
    class DependencyPathEdge < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyPathEdge'
      description "Edge for a paginated dependency path for SBOM occurrences"

      field :cursor, String, null: false,
        description: "Cursor for use in pagination."

      field :node, DependencyPathType, null: true,
        description: "Dependency path node."
    end
  end
end
