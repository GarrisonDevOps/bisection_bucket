# frozen_string_literal: true

module API
  module Entities
    class ScimIdentity < Grape::Entity
      expose :extern_uid, documentation: { type: 'String' }
      expose :group_id, documentation: { type: 'Integer' }
      expose :active, documentation: { type: 'Boolean' }
    end
  end
end
