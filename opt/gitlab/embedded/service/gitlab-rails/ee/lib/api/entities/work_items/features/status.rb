# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Status < Grape::Entity
          class StatusObject < Grape::Entity
            expose :id,
              documentation: {
                type: 'String',
                example: 'gid://gitlab/WorkItems::Statuses::SystemDefined::Status/1',
                desc: 'Global ID of the status. Shows whether the status is a default or a custom status.'
              },
              expose_nil: true do |status|
                status.to_gid.to_s
              end
            expose :name,
              documentation: { type: 'String', example: 'To do', desc: 'Name of the status.' },
              expose_nil: true
            expose :icon_name,
              documentation: {
                type: 'String', example: 'status-waiting',
                values: ::WorkItems::Statuses::SharedConstants::CATEGORY_ICONS.values,
                desc: 'Name of the icon for the status, set by its category.'
              },
              expose_nil: true
            expose :color,
              documentation: { type: 'String', example: '#737278', desc: 'Color of the status as a hex code.' },
              expose_nil: true
            # Custom statuses always return 0 (WorkItems::Statuses::Custom::Status#position).
            expose :position,
              documentation: {
                type: 'Integer', example: 0,
                desc: 'Position of the status in its category. Always 0 for custom statuses.'
              },
              expose_nil: true
            expose :description,
              documentation: {
                type: 'String',
                desc: 'Description of the status. Always null for default statuses.'
              },
              expose_nil: true
            expose :category,
              documentation: {
                type: 'String', example: 'to_do',
                values: ::WorkItems::Statuses::SharedConstants::CATEGORIES.keys.map(&:to_s),
                desc: 'Category of the status. Open categories are `triage`, `to_do`, and `in_progress`. ' \
                  'Closed categories are `done` and `canceled`.'
              },
              expose_nil: true do |status|
                status.category&.to_s
              end
          end

          expose :status,
            using: ::API::Entities::WorkItems::Features::Status::StatusObject,
            documentation: {
              type: 'Entities::WorkItems::Features::Status::StatusObject',
              desc: "Current status of the work item. If none is set, the lifecycle's open or closed default " \
                "status, depending on the work item's state. Null if the work item type has no status lifecycle."
            },
            expose_nil: true do |feature|
              feature.work_item.status_with_fallback
            end
        end
      end
    end
  end
end
