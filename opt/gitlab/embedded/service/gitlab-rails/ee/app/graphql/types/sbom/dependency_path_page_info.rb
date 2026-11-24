# frozen_string_literal: true

module Types
  module Sbom
    class DependencyPathPageInfo < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyPathPageInfo'

      field :has_previous_page, Boolean, null: false,
        description: "When paginating backwards, are there more items?."

      field :has_next_page, Boolean, null: false,
        description: "When paginating forwards, are there more items?."

      field :start_cursor, String,
        description: "When paginating backwards, the cursor to continue."

      field :end_cursor, String,
        description: "When paginating forwards, the cursor to continue."
    end
  end
end
