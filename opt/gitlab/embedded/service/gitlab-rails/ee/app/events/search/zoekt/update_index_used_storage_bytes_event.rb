# frozen_string_literal: true

module Search
  module Zoekt
    class UpdateIndexUsedStorageBytesEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {},
          'additionalProperties' => false
        }
      end
    end
  end
end
