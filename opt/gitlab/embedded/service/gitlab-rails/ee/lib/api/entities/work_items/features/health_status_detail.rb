# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class HealthStatusDetail < HealthStatus
          class RolledUpHealthStatus < Grape::Entity
            expose :health_status,
              documentation: {
                type: 'String',
                example: 'on_track',
                values: ::WorkItem.health_statuses.keys,
                desc: 'Health status that the count applies to.'
              }

            expose :count,
              documentation: {
                type: 'Integer', example: 4,
                desc: 'Number of open descendant work items, at any depth, with this health status.'
              }
          end

          # Built by WorkItems::Widgets::HealthStatus#rolled_up_health_status, which lists every health status.
          expose :rolled_up_health_status,
            using: ::API::Entities::WorkItems::Features::HealthStatusDetail::RolledUpHealthStatus,
            documentation: {
              type: 'Entities::WorkItems::Features::HealthStatusDetail::RolledUpHealthStatus',
              is_array: true,
              desc: 'Number of open descendant work items with each health status. ' \
                'Has one entry for every health status, including those with a count of 0.'
            }
        end
      end
    end
  end
end
