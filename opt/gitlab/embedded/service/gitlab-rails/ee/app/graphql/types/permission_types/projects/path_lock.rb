# frozen_string_literal: true

module Types
  module PermissionTypes
    module Projects
      class PathLock < BasePermissionType
        graphql_name 'PathLockPermissions'

        authorize_granular_token parent_authorizes: :read_code

        ability_field :destroy_path_lock
      end
    end
  end
end
