# frozen_string_literal: true

module Types
  module Namespaces
    class GroupMinimalAccessType < BaseObject
      graphql_name 'GroupMinimalAccess'

      # rubocop:disable Layout/LineLength -- otherwise description is creating unnecessary newlines.
      description 'Limited group data accessible to users without full group read access (e.g. non-members with READ_ADMIN_CICD admin custom role).'
      # rubocop:enable Layout/LineLength

      authorize :read_group_metadata

      implements GroupInterface

      field :avatar_url,
        type: GraphQL::Types::String,
        null: true,
        description: 'Avatar URL of the group.'
      # rubocop:disable GraphQL/ExtractType -- it does not make sense to have FullType
      field :full_name, GraphQL::Types::String, null: false,
        description: 'Full name of the group.'
      field :full_path, GraphQL::Types::ID, null: false,
        description: 'Full path of the group.'
      # rubocop:enable GraphQL/ExtractType
      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the group.'
      field :name, GraphQL::Types::String, null: false,
        description: 'Name of the group.'
      field :web_url,
        type: GraphQL::Types::String,
        null: true,
        description: 'Web URL of the group.'

      expose_permissions Types::PermissionTypes::Group

      def avatar_url
        object.avatar_url(only_path: false)
      end
    end
  end
end
