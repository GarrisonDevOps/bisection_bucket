# frozen_string_literal: true

module Vulnerabilities
  class BulkRedetectedEvent < Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'vulnerabilities' => {
            'type' => 'array',
            'items' => {
              'type' => 'object',
              'properties' => {
                'vulnerability_id' => { 'type' => 'integer' },
                'pipeline_id' => { 'type' => 'integer' },
                'timestamp' => { 'type' => 'string', 'format' => 'date-time' }
              }
            }
          }
        }
      }
    end
  end
end
