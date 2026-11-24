# frozen_string_literal: true

module Ai
  module DuoWorkflow
    module Concerns
      # The distinct MCP servers used by the configured agents of a project or a group,
      # for the readiness rows. The including class provides `user`, `mcp_consumer_params`
      # (a `project_id` or a `group_id` for ItemConsumersFinder) and `mcp_block_namespace`
      # (the namespace whose server blocks apply); it may narrow `mcp_agent_consumers`.
      module McpServers
        include ::Gitlab::Utils::StrongMemoize

        def mcp_servers_count
          mcp_servers.size
        end

        # Sorted case-insensitively with a bytewise tiebreak, so the surviving
        # casing of a duplicate name is deterministic.
        def mcp_server_names
          mcp_servers.map(&:name).sort_by { |name| [name.downcase, name] }.uniq(&:downcase)
        end

        private

        def mcp_servers
          agent_consumers = mcp_agent_consumers.with_items

          servers = ::Ai::Catalog::McpServersBatchLoader
            .batch_mcp_servers_for_item_versions(effective_version_ids(agent_consumers), user)
            .values.flatten.uniq

          reject_blocked_servers(servers)
        end
        strong_memoize_attr :mcp_servers

        def mcp_agent_consumers
          ::Ai::Catalog::ItemConsumersFinder
            .new(user, params: mcp_consumer_params.merge(item_types: [::Ai::Catalog::Item::AGENT_TYPE]))
            .execute
        end

        # A consumer pinned to an older version runs that version, not the latest. One
        # query resolves all pins; a pin that no longer resolves contributes nothing.
        def effective_version_ids(consumers)
          pinned, latest = consumers.partition(&:pinned_version_prefix)

          pinned_version_ids(pinned) + latest.map { |consumer| consumer.item.latest_version_id }
        end

        def pinned_version_ids(consumers)
          return [] if consumers.empty?

          pairs = consumers.map { |consumer| [consumer.ai_catalog_item_id, consumer.pinned_version_prefix] }
          ::Ai::Catalog::ItemVersion.for_item_version_pairs(pairs).pluck_primary_key
        end

        # Mirrors McpServers::ListService: a server blocked for the namespace never
        # reaches a run, so it does not count as connected.
        def reject_blocked_servers(servers)
          return servers if servers.empty?
          return servers unless Feature.enabled?(:mcp_server_block_enforcement, mcp_block_namespace.root_ancestor)

          blocked_ids = ::Ai::Catalog::McpServerBlock
            .blocked_server_ids_for(mcp_block_namespace, servers.map(&:id))
            .map(&:ai_catalog_mcp_server_id)

          servers.reject { |server| blocked_ids.include?(server.id) }
        end
      end
    end
  end
end
