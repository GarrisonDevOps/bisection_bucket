# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class Context < Grape::Entity
        expose :version, documentation: { type: 'String', example: '1.3.0' }
        expose :entities, using: ::API::Entities::Orbit::ContextEntity, documentation: { is_array: true }
      end
    end
  end
end
