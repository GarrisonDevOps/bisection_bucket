# frozen_string_literal: true

module Search
  module Zoekt
    class LostNodeEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {
            'zoekt_node_id' => { 'type' => 'integer' }
          },
          'required' => %w[zoekt_node_id]
        }
      end
    end
  end
end
