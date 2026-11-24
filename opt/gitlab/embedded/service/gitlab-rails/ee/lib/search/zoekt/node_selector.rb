# frozen_string_literal: true

module Search
  module Zoekt
    class NodeSelector
      include ::Gitlab::Loggable

      # Cache TTL for sticky sessions - 5 minutes provides good balance between
      # session consistency and load rebalancing
      CACHE_TTL = 5.minutes.to_i

      attr_reader :enabled_namespace, :search_level, :root_ancestor

      def self.for_project(project)
        root_ancestor = project.root_ancestor
        enabled_namespace = root_ancestor&.zoekt_enabled_namespace
        new(enabled_namespace: enabled_namespace, search_level: :project, root_ancestor: root_ancestor).nodes
      end

      def self.for_group(group)
        root_ancestor = group.root_ancestor
        enabled_namespace = root_ancestor&.zoekt_enabled_namespace
        new(enabled_namespace: enabled_namespace, search_level: :group, root_ancestor: root_ancestor).nodes
      end

      def self.for_global
        new(enabled_namespace: nil, search_level: :global, root_ancestor: nil).nodes
      end

      def initialize(enabled_namespace:, search_level:, root_ancestor:)
        @enabled_namespace = enabled_namespace
        @search_level = search_level
        @root_ancestor = root_ancestor
      end

      def nodes
        return global_nodes if global?

        validate_enabled_namespace!
        fetch_nodes_from_cache
      end

      private

      def global?
        search_level == :global
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Pluck is acceptable here for caching
      def fetch_nodes_from_cache
        cached_node_ids = Rails.cache.fetch(cache_key, expires_in: CACHE_TTL) do
          fetch_nodes.pluck(:id)
        end

        # Verify cached nodes are still online
        cached_nodes = all_searchable_search_nodes.id_in(cached_node_ids)

        # If all cached nodes are still online, return them
        return cached_nodes if cached_nodes.size == cached_node_ids.size

        # Some nodes went offline - invalidate cache and fetch fresh
        Rails.cache.delete(cache_key)
        fetch_nodes.tap do |fresh_nodes|
          Rails.cache.write(cache_key, fresh_nodes.pluck(:id), expires_in: CACHE_TTL)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def fetch_nodes
        result = ReplicaSelector.new(enabled_namespace).select
        validate_result!(result)

        result.nodes
      end

      def global_nodes
        all_searchable_search_nodes # Searches all replicas for now
      end

      def all_searchable_search_nodes
        @all_searchable_search_nodes ||= Node.for_search.searchable
      end

      def cache_key
        "zoekt:node_selection:#{enabled_namespace.id}:#{search_level}"
      end

      def validate_enabled_namespace!
        return if enabled_namespace.present?

        raise ArgumentError, "No enabled namespace found for root ancestor: #{root_ancestor.inspect}"
      end

      def validate_result!(result)
        if result.replica.blank?
          raise ArgumentError, "No ready replica found for namespace: #{enabled_namespace.inspect}"
        end

        return unless result.nodes.empty?

        # Unlike the two raises above, this one means the backend is genuinely unavailable rather
        # than misconfigured, so it degrades to a 503 instead of surfacing as an application bug.
        # That also makes the message reachable by GraphQL clients, so it carries ids only and the
        # row goes to the log.
        logger.error(build_structured_payload_labkit(
          message: 'No online nodes found for replica',
          zoekt_replica_id: result.replica.id,
          zoekt_enabled_namespace: enabled_namespace.attributes
        ))

        raise ::Search::Zoekt::Errors::NodeUnavailableError,
          "No online nodes found for replica #{result.replica.id} " \
            "in zoekt enabled namespace #{enabled_namespace.id}"
      end

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end
    end
  end
end
