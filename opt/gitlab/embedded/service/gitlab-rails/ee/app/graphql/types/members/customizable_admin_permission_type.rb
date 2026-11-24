# frozen_string_literal: true

module Types
  module Members
    # rubocop: disable Graphql/AuthorizeTypes -- globally available
    class CustomizableAdminPermissionType < ::Types::MemberRoles::CustomizablePermissionType
      graphql_name 'CustomizableAdminPermission'

      field :requirements,
        type: [Types::Members::CustomizableAdminPermissionsEnum],
        null: true,
        description: 'Requirements of the permission.'

      field :value,
        type: Types::Members::CustomizableAdminPermissionsEnum,
        null: false,
        description: 'Value of the permission.',
        method: :itself

      def permission
        ::Gitlab::CustomRoles::Definition.admin[object]
      end
      strong_memoize_attr :permission
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
