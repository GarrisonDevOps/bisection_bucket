# frozen_string_literal: true

module API
  module Entities
    module Govern
      class Trigger < Grape::Entity
        expose :id, documentation: { type: 'String', example: 'deployment_requested' }
        expose :name, documentation: { type: 'String', example: 'Deployment' }
        expose :kind, documentation: { type: 'String', example: 'gate' }
      end
    end
  end
end
