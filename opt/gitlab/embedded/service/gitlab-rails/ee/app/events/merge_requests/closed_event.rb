# frozen_string_literal: true

module MergeRequests
  class ClosedEvent < Gitlab::EventStore::Event
    SOURCE_TYPES = {
      dependency_management_auto_remediation: 'dependency_management_auto_remediation'
    }.freeze

    def schema
      {
        'type' => 'object',
        'required' => %w[
          merge_request_id
        ],
        'properties' => {
          'merge_request_id' => { 'type' => 'integer' },
          'source' => {
            'type' => 'string',
            'enum' => SOURCE_TYPES.values
          }
        }
      }
    end
  end
end
