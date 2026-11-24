# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class Status < Grape::Entity
        expose :id,
          documentation: {
            type: 'Integer', example: 1,
            desc: 'ID of the status. Default and custom statuses are numbered separately.'
          },
          expose_nil: true
        expose :name,
          documentation: { type: 'String', desc: 'Name of the status.', example: 'To do' },
          expose_nil: true
        expose :icon_name,
          documentation: {
            type: 'String', example: 'status-waiting',
            values: ::WorkItems::Statuses::SharedConstants::CATEGORY_ICONS.values,
            desc: 'Name of the icon for the status, set by its category.'
          },
          expose_nil: true
        expose :color,
          documentation: { type: 'String', desc: 'Color of the status as a hex code.', example: '#737278' },
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
            type: 'String', desc: 'Description of the status. Always null for default statuses.'
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
    end
  end
end
