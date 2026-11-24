# frozen_string_literal: true

module Types
  module Members
    # rubocop: disable Graphql/AuthorizeTypes -- standard roles are readable for everyone
    class StandardRoleType < BaseObject
      graphql_name 'StandardRole'
      description 'Represents a standard role'

      include ::Gitlab::Utils::StrongMemoize
      include MemberRolesHelper

      implements Types::Members::RoleInterface

      # rubocop:disable Graphql::AccessLevelEnum -- Introduced before the cop
      field :access_level,
        GraphQL::Types::Int,
        null: false,
        description: 'Access level as a number.'
      # rubocop:enable Graphql::AccessLevelEnum

      def id
        "gid://gitlab/StandardRole/#{access_level_enum}"
      end

      def description
        Types::MemberAccessLevelEnum.values[access_level_enum].description
      end

      def details_path
        enum = access_level_enum
        group = object[:group]
        enum.define_singleton_method(:namespace) { group }

        member_role_details_path(enum)
      end

      def access_level_enum
        access_level = object[:access_level]
        access_level_enums[access_level].upcase
      end

      def access_level_enums
        Types::MemberAccessLevelEnum.enum.invert
      end
      strong_memoize_attr :access_level_enums
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
