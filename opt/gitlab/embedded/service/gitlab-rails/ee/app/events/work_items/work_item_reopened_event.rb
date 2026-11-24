# frozen_string_literal: true

module WorkItems
  class WorkItemReopenedEvent < Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'required' => %w[id namespace_id],
        'properties' => {
          'id' => { 'type' => 'integer' },
          'namespace_id' => { 'type' => 'integer' }
        }
      }
    end
  end
end
