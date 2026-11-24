# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class Type < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the work item type.' }
        expose :name,
          documentation: { type: 'String', example: 'Issue', desc: 'Name of the work item type, for example `Issue`.' }
        expose :icon_name,
          documentation: {
            type: 'String', example: 'work-item-issue',
            desc: 'Name of the icon for the work item type.'
          }
      end
    end
  end
end
