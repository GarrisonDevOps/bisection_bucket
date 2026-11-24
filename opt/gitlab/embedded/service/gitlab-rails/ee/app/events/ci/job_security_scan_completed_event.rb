# frozen_string_literal: true

module Ci
  class JobSecurityScanCompletedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'required' => ['job_id'],
        'properties' => {
          'job_id' => { 'type' => 'integer' }
        }
      }
    end
  end
end
