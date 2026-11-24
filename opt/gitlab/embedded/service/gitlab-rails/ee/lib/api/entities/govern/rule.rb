# frozen_string_literal: true

module API
  module Entities
    module Govern
      class Rule < Grape::Entity
        expose :id, documentation: { type: 'String', example: 'environment' }
        expose :name, documentation: { type: 'String', example: 'Environment' }
      end
    end
  end
end
