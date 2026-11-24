# frozen_string_literal: true

module API
  module Entities
    class ProtectedBranch < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the protected branch.' }
      expose :name, documentation: { type: 'String', example: 'main', desc: 'Name of the protected branch.' }
      expose :push_access_levels, using: ::API::Entities::ProtectedRefAccess,
        documentation: { type: '::API::Entities::ProtectedRefAccess', is_array: true,
                         desc: 'Array of push access level configurations.' }
      expose :merge_access_levels, using: ::API::Entities::ProtectedRefAccess,
        documentation: { type: '::API::Entities::ProtectedRefAccess', is_array: true,
                         desc: 'Array of merge access level configurations.' }
      expose :allow_force_push,
        documentation: { type: 'Boolean', desc: 'If `true`, force push is allowed on the branch.' }
    end
  end
end

API::Entities::ProtectedBranch.prepend_mod_with('API::Entities::ProtectedBranch')
