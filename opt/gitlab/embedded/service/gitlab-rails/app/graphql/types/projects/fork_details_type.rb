# frozen_string_literal: true

module Types
  module Projects
    # rubocop: disable Graphql/AuthorizeTypes
    class ForkDetailsType < BaseObject
      graphql_name 'ForkDetails'
      description 'Details of the fork project compared to its upstream project.'

      # ForkDetailsResolver checks the token on the fork; the counts also read the upstream.
      authorize_granular_token permissions: :read_code, boundary: :fork_source, boundary_type: :project

      field :ahead, GraphQL::Types::Int,
        null: true,
        calls_gitaly: true,
        description: 'Number of commits ahead of the upstream default branch.'

      field :behind, GraphQL::Types::Int,
        null: true,
        calls_gitaly: true,
        description: 'Number of commits behind the upstream default branch.'

      field :is_syncing, GraphQL::Types::Boolean,
        null: true,
        method: :syncing?,
        description: 'Indicates if there is a synchronization in progress.'

      field :has_conflicts, GraphQL::Types::Boolean,
        null: true,
        method: :has_conflicts?,
        description: 'Indicates if the last synchronization failed because of a merge conflict ' \
          'with the upstream default branch.'

      def ahead
        counts[:ahead]
      end

      def behind
        counts[:behind]
      end

      def counts
        @counts ||= object.counts
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
