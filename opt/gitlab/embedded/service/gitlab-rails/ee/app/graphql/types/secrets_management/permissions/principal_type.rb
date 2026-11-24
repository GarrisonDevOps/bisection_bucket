# frozen_string_literal: true

module Types
  module SecretsManagement
    module Permissions
      class PrincipalType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- This is not necessary because the superclass declares the authorization
        graphql_name 'Principal'
        description 'Representation of who is provided access to. For eg: User/Role/MemberRole.'

        authorize_granular_token parent_authorizes: :read_secrets_permission

        field :id, GraphQL::Types::ID,
          null: false,
          description: 'ID of the principal (User, MemberRole, Role).'

        field :type, Types::SecretsManagement::Permissions::PrincipalTypeEnum,
          null: false,
          description: 'Name of the principal (User, MemberRole, Role).'

        field :user,
          Types::UserType,
          null: true,
          description: "User who is provided access to."

        field :user_role_id, GraphQL::Types::String,
          null: true,
          description: 'RoleID of the user.'

        def id
          object[:id] || object['id']
        end

        def type
          object[:type] || object['type']
        end

        def user
          user_record if type == 'User'
        end

        def user_role_id
          return unless type == 'User' && resource_id

          ::Gitlab::Graphql::Lazy.with_value(user_record) do |user|
            next nil unless user

            resource_class = resource_type.safe_constantize

            if resource_class == Project
              user.max_member_access_for_project(resource_id)&.to_s
            elsif resource_class == Group
              user.max_member_access_for_group(resource_id)&.to_s
            end
          end
        end

        private

        def user_record
          Gitlab::Graphql::Loaders::BatchModelLoader.new(User, id).find
        end

        def resource_id
          @resource_id ||= (object[:resource_id] || object['resource_id'])&.to_i
        end

        def resource_type
          @resource_type ||= object[:resource_type] || object['resource_type']
        end
      end
    end
  end
end
