# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class RequirementLegacy < Grape::Entity
          expose :legacy_iid,
            documentation: {
              type: 'Integer', example: 1,
              desc: 'Internal ID of the legacy requirement linked to the work item. Null if none is linked.'
            },
            expose_nil: true
        end
      end
    end
  end
end
