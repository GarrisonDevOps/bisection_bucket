# frozen_string_literal: true

module API
  module Entities
    class SamlGroupLink < Grape::Entity
      expose :saml_group_name, as: :name, documentation: {
        type: 'String', example: 'saml-group-1',
        desc: 'Name of the SAML group.'
      }
      # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
      expose :access_level, documentation: {
        type: 'Integer', example: 40,
        desc: 'Default access level for members of the SAML group. Possible values: `5` (Minimal access), `10` ' \
          '(Guest), `15` (Planner), `20` (Reporter), `25` (Security Manager), `30` (Developer), `40` (Maintainer), ' \
          'or `50` (Owner).'
      }
      # rubocop:enable API/AccessLevelStringType
      expose :member_role_id,
        documentation: {
          type: 'Integer', format: 'int64', example: 12,
          desc: 'ID of the custom member role for members of the SAML group. Returned only when custom roles are ' \
            'enabled for the group.'
        }, if: ->(instance, _options) do
          instance.group.custom_roles_enabled?
        end
      expose :provider, documentation: {
        type: 'String', example: 'saml',
        desc: 'Unique provider name that must match for this group link to be applied.'
      }
    end
  end
end
