# frozen_string_literal: true

module Search
  module Zoekt
    class NodeWithNegativeUnclaimedStorageEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {
            'node_ids' => { 'type' => 'array', 'items' => { 'type' => 'integer' } }
          },
          'required' => %w[node_ids]
        }
      end
    end
  end
end
