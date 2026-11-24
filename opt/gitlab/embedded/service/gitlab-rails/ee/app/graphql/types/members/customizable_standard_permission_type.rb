# frozen_string_literal: true

module Types
  module Members
    # rubocop: disable Graphql/AuthorizeTypes -- globally available
    class CustomizableStandardPermissionType < ::Types::MemberRoles::CustomizablePermissionType
      graphql_name 'CustomizableStandardPermission'

      field :requirements,
        type: [Types::Members::CustomizableStandardPermissionsEnum],
        null: true,
        description: 'Requirements of the permission.'

      field :value,
        type: Types::Members::CustomizableStandardPermissionsEnum,
        null: false,
        description: 'Value of the permission.',
        method: :itself

      field :available_for,
        type: [GraphQL::Types::String],
        null: false,
        description: 'Objects the permission is available for.'

      field :enabled_for_group_access_levels,
        type: [Types::AccessLevelEnum],
        null: true,
        description: 'Group access levels from which the permission is allowed.'

      field :enabled_for_project_access_levels, # rubocop: disable GraphQL/ExtractType -- in use on production and no advantage to extracting it
        type: [Types::AccessLevelEnum],
        null: true,
        description: 'Project access levels from which the permission is allowed.'

      def permission
        MemberRole.all_customizable_standard_permissions[object]
      end
      strong_memoize_attr :permission

      def available_for
        result = []
        result << :project if permission[:project_ability]
        result << :group if permission[:group_ability]

        result
      end

      def enabled_for_group_access_levels
        permission[:enabled_for_group_access_levels]
      end

      def enabled_for_project_access_levels
        permission[:enabled_for_project_access_levels]
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
