# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class McpServerSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Mcp::NamespaceAccessCacheResetWorker,
            to: ::Mcp::ServerSettingsChangedEvent
        end
      end
    end
  end
end
