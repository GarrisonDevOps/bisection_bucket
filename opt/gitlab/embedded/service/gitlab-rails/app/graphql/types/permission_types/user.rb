# frozen_string_literal: true

module Types
  module PermissionTypes
    class User < BasePermissionType
      graphql_name 'UserPermissions'

      authorize_granular_token parent_authorizes: :read_user

      permission_field :create_snippet

      def create_snippet
        Ability.allowed?(context[:current_user], :create_snippet)
      end
    end
  end
end
