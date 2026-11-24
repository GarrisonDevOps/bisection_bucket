# frozen_string_literal: true

module Analytics
  class ClickHouseForAnalyticsEnabledEvent < Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'required' => %w[enabled_at],
        'properties' => {
          'enabled_at' => { 'type' => 'string', 'format' => 'date-time' }
        }
      }
    end
  end
end
