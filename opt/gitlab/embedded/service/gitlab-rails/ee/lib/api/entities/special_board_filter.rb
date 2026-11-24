# frozen_string_literal: true

module API
  module Entities
    class SpecialBoardFilter < Grape::Entity
      expose :title, documentation: { type: 'String', example: 'Any' }
    end
  end
end
