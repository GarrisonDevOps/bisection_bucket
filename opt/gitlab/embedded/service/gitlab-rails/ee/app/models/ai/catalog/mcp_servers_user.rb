# frozen_string_literal: true

module Ai
  module Catalog
    class McpServersUser < ApplicationRecord
      self.table_name = "ai_catalog_mcp_servers_users"

      encrypts :token
      encrypts :refresh_token

      validates :ai_catalog_mcp_server_id, :user_id, presence: true
      validates :user_id, uniqueness: { scope: :ai_catalog_mcp_server_id }

      belongs_to :organization, class_name: 'Organizations::Organization', optional: false
      belongs_to :mcp_server, class_name: 'Ai::Catalog::McpServer', foreign_key: :ai_catalog_mcp_server_id,
        inverse_of: :mcp_servers_users
      belongs_to :user
    end
  end
end
