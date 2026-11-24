# frozen_string_literal: true

module API
  module Entities
    module Govern
      class Action < Grape::Entity
        expose :id, documentation: { type: 'String', example: 'block' }
        expose :name, documentation: { type: 'String', example: 'Block' }
      end
    end
  end
end
