# frozen_string_literal: true

module Ai
  module Messaging
    # Registry of messaging adapters keyed by adapter_key. A neutral home so
    # services and workers resolve adapters without reaching into each other's
    # internals.
    module AdapterRegistry
      ADAPTERS = {
        Adapters::Slack.adapter_key => Adapters::Slack,
        Adapters::GitlabDuoNote.adapter_key => Adapters::GitlabDuoNote,
        Adapters::Webhook.adapter_key => Adapters::Webhook
      }.freeze

      def self.[](adapter_key)
        ADAPTERS[adapter_key]
      end

      def self.private_to_invoker_keys
        ADAPTERS.filter_map { |key, adapter| key if adapter.private_to_invoker? }
      end
    end
  end
end
