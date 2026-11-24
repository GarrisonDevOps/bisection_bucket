# frozen_string_literal: true

module Vulnerabilities
  class BulkDismissedEvent < Gitlab::EventStore::Event
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
                'project_id' => { 'type' => 'integer' },
                'namespace_id' => { 'type' => 'integer' },
                'dismissal_reason' => { 'type' => 'string' },
                'comment' => { 'type' => %w[string null] },
                'user_id' => { 'type' => 'integer' }
              }
            }
          }
        }
      }
    end
  end
end
