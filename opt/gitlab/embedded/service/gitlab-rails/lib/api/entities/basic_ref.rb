# frozen_string_literal: true

module API
  module Entities
    class BasicRef < Grape::Entity
      expose :type,
        documentation: { type: 'String', example: 'tag', desc: 'Type of the reference. Either `branch` or `tag`.' }
      expose :name, documentation: { type: 'String', example: 'v1.1.0', desc: 'Name of the branch or tag.' }
    end
  end
end
