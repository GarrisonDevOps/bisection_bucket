# frozen_string_literal: true

module Search
  module Zoekt
    class IndexMarkedAsToDeleteEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {
            'index_ids' => { 'type' => 'array', 'items' => { 'type' => 'integer' } }
          }
        }
      end
    end
  end
end
