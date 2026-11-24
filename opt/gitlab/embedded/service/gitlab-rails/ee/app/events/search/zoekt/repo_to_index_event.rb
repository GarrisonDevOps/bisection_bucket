# frozen_string_literal: true

module Search
  module Zoekt
    class RepoToIndexEvent < ::Gitlab::EventStore::Event
      def schema
        {
          'type' => 'object',
          'properties' => {
            'zoekt_repo_ids' => { 'type' => 'array', 'items' => { 'type' => 'integer' } }
          }
        }
      end
    end
  end
end
