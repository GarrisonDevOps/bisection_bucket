# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class HealthStatus < Grape::Entity
          expose :health_status,
            documentation: {
              type: 'String',
              example: 'needs_attention',
              values: ::WorkItem.health_statuses.keys,
              desc: 'Health status of the work item: `on_track`, `needs_attention`, or `at_risk`. Null if not set.'
            },
            expose_nil: true
        end
      end
    end
  end
end
