# frozen_string_literal: true

module Gitlab
  module Graphql
    module ArtifactRegistry
      class RepositoriesPage < ::Gitlab::Graphql::ExternallyPaginatedArray
        attr_reader :permissions

        def initialize(previous_cursor, next_cursor, *args, permissions:, **options)
          super(previous_cursor, next_cursor, *args, **options)
          @permissions = permissions
        end
      end
    end
  end
end
