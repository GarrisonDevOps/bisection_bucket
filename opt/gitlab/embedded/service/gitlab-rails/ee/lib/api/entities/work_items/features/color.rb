# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Color < Grape::Entity
          expose :color,
            documentation: {
              type: 'String', example: '#A8DADC',
              desc: 'Color of the work item as a hex code. Defaults to `#1068bf` if no color is set.'
            },
            expose_nil: true

          # Gitlab::Color#contrast returns one of two fixed colors, depending on how light `color` is.
          expose :text_color,
            documentation: {
              type: 'String', example: '#1F1E24', values: ['#1F1E24', '#FFFFFF'],
              desc: 'Text color that contrasts with `color`: `#1F1E24` for a light color, `#FFFFFF` for a dark color.'
            },
            expose_nil: true
        end
      end
    end
  end
end
