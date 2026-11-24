# frozen_string_literal: true

module Mcp
  class GroupSettings
    def initialize(group)
      @group = group
    end

    def setting_available?
      group.root? && ::Gitlab::Saas.feature_available?(:mcp_server_saas_only)
    end

    def mcp_server_enabled?
      group.root? && !!group.namespace_settings&.mcp_server_enabled?
    end

    protected

    attr_reader :group
  end
end
