# frozen_string_literal: true

module Ai
  module Catalog
    # Resolves the block status of MCP servers for a single container (group or project namespace),
    # batching across all servers in the same GraphQL query. A server is BLOCKED when blocked directly
    # on the container, or BLOCKED_BY_ANCESTOR when blocked on one of its ancestors (group +
    # descendants kill-switch, which includes the projects inside a blocked group).
    class McpServerBlockStatusBatchLoader
      ACTIVE = 'active'
      BLOCKED = 'blocked'
      BLOCKED_BY_ANCESTOR = 'blocked_by_ancestor'

      def self.load_for(mcp_server, namespace)
        new(namespace).load(mcp_server)
      end

      def initialize(namespace)
        @namespace = namespace
      end

      def load(mcp_server)
        BatchLoader::GraphQL.for(mcp_server.id).batch(key: namespace.id, default_value: ACTIVE) do |server_ids, loader|
          # `self_and_ancestor_ids` (traversal_ids) rather than the `self_and_ancestors` relation:
          # on a project-namespace the relation is scoped to `type = 'Project'`, which would drop the
          # ancestor groups and miss group-level blocks.
          ancestor_ids = namespace.self_and_ancestor_ids

          blocks_by_server = ::Ai::Catalog::McpServerBlock
            .for_namespaces(ancestor_ids)
            .for_servers(server_ids)
            .group_by(&:ai_catalog_mcp_server_id)

          server_ids.each do |server_id|
            loader.call(server_id, status_for(blocks_by_server[server_id]))
          end
        end
      end

      private

      attr_reader :namespace

      def status_for(blocks)
        return ACTIVE if blocks.blank?
        return BLOCKED if blocks.any? { |block| block.namespace_id == namespace.id }

        BLOCKED_BY_ANCESTOR
      end
    end
  end
end
