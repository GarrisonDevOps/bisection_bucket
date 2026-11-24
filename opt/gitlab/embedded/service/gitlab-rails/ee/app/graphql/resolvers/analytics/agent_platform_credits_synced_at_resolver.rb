# frozen_string_literal: true

module Resolvers
  module Analytics
    # Reuses the aggregation engines' source loading and authorization, so the timestamp is
    # readable by exactly the users who can query the credits it describes.
    class AgentPlatformCreditsSyncedAtResolver < ::Resolvers::Analytics::Aggregation::EngineResolver::BaseEngineResolver
      include ::Analytics::RequiresDapImpactV1

      type ::Types::TimeType, null: true

      self.resource_ability = :read_pro_ai_analytics
      self.implicit_sources_finder_params = { with_duo_agent_platform_enabled: true }

      def resolve(**arguments)
        sources = aggregation_sources(arguments)

        ::Ai::DuoWorkflows::SessionCredits::SyncFreshness.oldest_completed_at(root_namespace_ids(sources))
      rescue ::Gitlab::Graphql::Errors::ResourceNotAvailable
        # Unlike the engines this needs no arguments, so queries selecting every field pick it up.
        # A single value the user cannot read resolves to null, as GraphQL authorization does.
        nil
      end

      private

      # Self-managed syncs credits once for the whole instance, not per root namespace.
      def root_namespace_ids(sources)
        return [nil] unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        sources.map do |source|
          namespace = source.is_a?(::Project) ? source.namespace : source

          namespace.traversal_ids.first
        end
      end
    end
  end
end
