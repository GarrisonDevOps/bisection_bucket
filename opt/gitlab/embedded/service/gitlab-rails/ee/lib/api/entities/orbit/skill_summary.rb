# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class SkillSummary < Grape::Entity
        expose(:name, documentation: { type: 'String', example: 'orbit' }) { |skill| skill['name'] }
        expose(:version, documentation: { type: 'String', example: '0.29.0' }) { |skill| skill['version'] }
        expose(:compatibility, documentation: { type: 'String', example: 'Orbit CLI' }) do |skill|
          skill['compatibility']
        end
        expose(:description, documentation: { type: 'String', example: 'Use the glab orbit CLI.' }) do |skill|
          skill['description']
        end
      end
    end
  end
end
