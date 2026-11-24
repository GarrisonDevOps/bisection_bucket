# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class Label < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the label.' }
        expose :title, documentation: { type: 'String', example: 'bug', desc: 'Title of the label.' }
        expose :description,
          documentation: {
            type: 'String', example: 'Bug reports',
            desc: 'Description of the label. Null or empty if the label has no description.'
          }
        expose :color,
          documentation: {
            type: 'String', example: '#FF0000',
            desc: 'Background color of the label, as a hex code. Defaults to `#6699cc` if no color is set.'
          } do |label|
          label.color.to_s
        end
        expose :text_color,
          documentation: {
            type: 'String', example: '#FFFFFF',
            desc: 'Text color that contrasts with the label color: `#1F1E24` for a light color, ' \
              '`#FFFFFF` for a dark color.'
          }
      end
    end
  end
end
