# frozen_string_literal: true

module Mcp
  class ServerSettingsChangedEvent < ::Gitlab::EventStore::Event
    NAMESPACE_SETTINGS = %w[mcp_server_enabled].freeze

    def schema
      {
        'type' => 'object',
        'properties' => {
          'group_id' => { 'type' => 'integer' }
        },
        'required' => %w[group_id]
      }
    end
  end
end
