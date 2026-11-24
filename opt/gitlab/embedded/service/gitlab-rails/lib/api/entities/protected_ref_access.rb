# frozen_string_literal: true

module API
  module Entities
    class ProtectedRefAccess < Grape::Entity
      expose :id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the access level configuration.' }
      # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
      expose :access_level,
        documentation: { type: 'Integer', example: 40, desc: 'Access level the configuration grants.' }
      # rubocop:enable API/AccessLevelStringType
      expose :humanize, as: :access_level_description,
        documentation: { type: 'String', example: 'Maintainers',
                         desc: 'Human-readable description of the access level.' }
      expose :deploy_key_id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the deploy key with access.' },
        if: ->(access) { access.has_attribute?(:deploy_key_id) }
    end
  end
end

API::Entities::ProtectedRefAccess.prepend_mod_with('API::Entities::ProtectedRefAccess')
