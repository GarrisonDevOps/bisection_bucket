# frozen_string_literal: true

module Ai
  module Catalog
    class McpServersBatchLoader
      class << self
        # Batches on the loaded versions themselves, so the definitions GraphQL already
        # holds are not read from the database a second time.
        def load_for(agent_version, current_user)
          BatchLoader::GraphQL.for(agent_version).batch(default_value: []) do |agent_versions, loader|
            results = mcp_servers_for_versions(agent_versions, current_user)
            agent_versions.each { |version| loader.call(version, results.fetch(version.id, [])) }
          end
        end

        def batch_mcp_servers_for_item_versions(item_version_ids, current_user)
          item_version_ids = Array(item_version_ids).uniq
          return {} if item_version_ids.empty?

          # The access check lives in mcp_servers_for_versions; the relation stays unloaded until it passes.
          results = mcp_servers_for_versions(::Ai::Catalog::ItemVersion.id_in(item_version_ids), current_user)

          item_version_ids.index_with { |id| results.fetch(id, []) }
        end

        private

        def mcp_servers_for_versions(item_versions, current_user)
          return {} unless ::Ai::Catalog.mcp_servers_available?(current_user)

          item_versions = item_versions.to_a
          return {} if item_versions.empty?

          allowed_org_ids = allowed_organization_ids_for(item_versions, current_user)
          readable_versions = item_versions.select { |version| allowed_org_ids.include?(version.organization_id) }
          mcp_servers_by_id = load_mcp_servers(readable_versions.flat_map { |version| server_ids_for(version) }.uniq)

          item_versions.to_h do |version|
            next [version.id, []] unless readable_versions.include?(version)

            [version.id, server_ids_for(version).filter_map { |sid| mcp_servers_by_id[sid] }]
          end
        end

        def allowed_organization_ids_for(item_versions, current_user)
          organization_ids = item_versions.filter_map(&:organization_id).uniq
          return Set.new if organization_ids.empty?
          return organization_ids.to_set if Ability.allowed?(current_user, :admin_all_resources)

          ::Organizations::Organization.with_user(current_user).id_in(organization_ids).pluck_primary_key.to_set
        end

        # The create and update mutations cap the list, so a read takes it as is.
        def server_ids_for(version)
          Array(version.def_mcp_servers).uniq
        end

        def load_mcp_servers(mcp_server_ids)
          return {} if mcp_server_ids.empty?

          ::Ai::Catalog::McpServer.id_in(mcp_server_ids).index_by(&:id)
        end
      end
    end
  end
end
