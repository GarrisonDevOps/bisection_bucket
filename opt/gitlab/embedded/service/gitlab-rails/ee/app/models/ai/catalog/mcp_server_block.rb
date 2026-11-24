# frozen_string_literal: true

module Ai
  module Catalog
    class McpServerBlock < ApplicationRecord
      self.table_name = "ai_catalog_mcp_server_blocks"

      belongs_to :organization, class_name: 'Organizations::Organization', optional: false
      belongs_to :namespace, optional: false
      belongs_to :mcp_server,
        class_name: 'Ai::Catalog::McpServer',
        foreign_key: :ai_catalog_mcp_server_id,
        inverse_of: :blocks,
        optional: false
      belongs_to :created_by, class_name: 'User', optional: true

      validates :namespace_id, uniqueness: { scope: :ai_catalog_mcp_server_id }

      scope :for_namespaces, ->(namespace_ids) { where(namespace_id: namespace_ids) }
      scope :for_servers, ->(server_ids) { where(ai_catalog_mcp_server_id: server_ids) }

      def self.blocked_server_ids_for(namespace, server_ids)
        for_namespaces(namespace.self_and_ancestor_ids)
          .for_servers(server_ids)
          .select(:ai_catalog_mcp_server_id)
      end

      # Race-safe, idempotent creation of a block for the namespace + server. Returns the record.
      def self.block!(namespace:, mcp_server:, created_by:)
        attrs = {
          organization_id: mcp_server.organization_id,
          namespace_id: namespace.id,
          ai_catalog_mcp_server_id: mcp_server.id
        }

        find_or_create_by!(attrs) { |block| block.created_by = created_by }
      rescue ActiveRecord::RecordNotUnique
        find_by!(attrs)
      rescue ActiveRecord::RecordInvalid => e
        # The uniqueness validation runs before the insert, so a racing loser sees this rather
        # than RecordNotUnique.
        raise unless e.record.errors.of_kind?(:namespace_id, :taken)

        find_by!(attrs)
      end

      # Removes the namespace's own block for the server (allow). No-op when absent.
      def self.unblock!(namespace:, mcp_server:)
        for_namespaces([namespace.id]).for_servers([mcp_server.id]).delete_all
      end
    end
  end
end
