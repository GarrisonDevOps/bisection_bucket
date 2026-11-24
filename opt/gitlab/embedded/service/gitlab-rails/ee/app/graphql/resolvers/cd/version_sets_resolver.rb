# frozen_string_literal: true

module Resolvers
  module Cd
    class VersionSetsResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::VersionSetType.connection_type, null: true

      alias_method :application, :object

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search version sets by name or description.'

      argument :statuses, [::Types::Cd::VersionSetStatusEnum],
        required: false,
        description: 'Filter releases by status.'

      def resolve_with_lookahead(search: nil, statuses: nil, **)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        version_sets = application.version_sets
        version_sets = version_sets.search(search) if search.present?
        version_sets = version_sets.for_statuses(statuses) if statuses.present?

        apply_lookahead(version_sets)
      end

      private

      def preloads
        {
          version_set_entries: [:version_set_entries],
          rollouts: [:rollouts]
        }
      end
    end
  end
end
