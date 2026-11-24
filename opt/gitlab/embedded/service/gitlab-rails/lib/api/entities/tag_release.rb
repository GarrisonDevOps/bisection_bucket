# frozen_string_literal: true

module API
  module Entities
    # deprecated old Release representation
    class TagRelease < Grape::Entity
      expose :tag, as: :tag_name, documentation: { type: 'String', example: '1.0.0', desc: 'Tag name of the release.' }
      expose :description,
        documentation: { type: 'String', example: 'Amazing release. Wow', desc: 'Description of the release.' }
    end
  end
end
