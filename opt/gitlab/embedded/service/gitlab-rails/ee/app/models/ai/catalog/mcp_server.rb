# frozen_string_literal: true

module Ai
  module Catalog
    class McpServer < ApplicationRecord
      self.table_name = "ai_catalog_mcp_servers"

      encrypts :oauth_client_secret

      alias_attribute :oauth_client_id, :oauth_client_xid

      validates :organization, :url, :transport, :auth_type, :name, presence: true
      validates :name, length: { maximum: 255 }
      validates :description, length: { maximum: 2_048 }, allow_blank: true
      validates :url, length: { maximum: 2_048 }, addressable_url: {
        enforce_sanitization: true,
        allow_local_network: ->(_) { Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services? },
        allow_localhost: ->(_) { Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services? }
      }
      validates :url, uniqueness: { scope: :organization_id }
      validates :homepage_url, length: { maximum: 2_048 }, allow_blank: true
      validates :oauth_client_id, length: { maximum: 255 }, allow_blank: true

      belongs_to :organization, class_name: 'Organizations::Organization', optional: false
      belongs_to :created_by, class_name: 'User'

      has_many :mcp_servers_users,
        class_name: 'Ai::Catalog::McpServersUser',
        foreign_key: :ai_catalog_mcp_server_id,
        inverse_of: :mcp_server

      has_many :blocks,
        class_name: 'Ai::Catalog::McpServerBlock',
        foreign_key: :ai_catalog_mcp_server_id,
        inverse_of: :mcp_server

      enum :transport, {
        http: 0
      }

      enum :auth_type, {
        oauth: 0,
        no_auth: 1
      }

      scope :in_organization, ->(organization) { where(organization: organization) }

      def connected_by_user?(user)
        return false unless user

        mcp_servers_users.exists?(user_id: user.id)
      end

      def resolved_oauth_client_secret
        return Gitlab::CurrentSettings.slack_app_secret if McpServers::SlackHelper.gitlab_slack_app_server?(self)

        oauth_client_secret
      end
    end
  end
end
