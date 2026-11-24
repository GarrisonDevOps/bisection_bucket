# frozen_string_literal: true

module API
  module Entities
    class MemberRole < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 2 }
      expose :namespace_id, as: :group_id, documentation: { type: 'Integer', format: 'int64', example: 2 }
      expose :name, documentation: { type: 'String', example: 'Custom guest' }
      expose :description, documentation: { type: 'String', example: 'Guest user who can also read_code' }
      # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
      expose :base_access_level, documentation: {
        type: 'Integer',
        example: 40,
        description: "Access level. Valid values #{::MemberRole.levels_sentence}.",
        values: ::MemberRole::LEVELS
      }
      # rubocop:enable API/AccessLevelStringType

      ::MemberRole.all_customizable_permissions.each_key do |permission_name|
        expose permission_name, documentation: { type: 'Boolean' }, default: false
      end
    end
  end
end
