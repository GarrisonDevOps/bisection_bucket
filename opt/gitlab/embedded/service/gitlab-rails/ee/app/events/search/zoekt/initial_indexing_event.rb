# frozen_string_literal: true

module Search
  module Zoekt
    class InitialIndexingEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {
            'index_id' => { 'type' => 'integer' }
          },
          'required' => %w[index_id]
        }
      end
    end
  end
end
