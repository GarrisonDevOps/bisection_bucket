# frozen_string_literal: true

module Types
  module MemberRoles
    # rubocop: disable Graphql/AuthorizeTypes
    class CustomizablePermissionType < BaseObject
      graphql_name 'CustomizablePermission'

      include Gitlab::Utils::StrongMemoize

      field :description,
        type: GraphQL::Types::String,
        null: true,
        description: 'Description of the permission.'

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Localized name of the permission.'

      field :requirements,
        type: [Types::MemberRoles::PermissionsEnum],
        null: true,
        description: 'Requirements of the permission.'

      field :value,
        type: Types::MemberRoles::PermissionsEnum,
        null: false,
        description: 'Value of the permission.',
        method: :itself

      def description
        _(permission[:description])
      end

      def name
        permission[:title] || object.to_s.humanize
      end

      def requirements
        permission[:requirements].presence&.map(&:to_sym)
      end

      def permission
        MemberRole.all_customizable_permissions[object]
      end
      strong_memoize_attr :permission
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
