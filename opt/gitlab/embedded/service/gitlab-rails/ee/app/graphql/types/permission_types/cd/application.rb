# frozen_string_literal: true

module Types
  module PermissionTypes
    module Cd
      class Application < BasePermissionType
        graphql_name 'CdApplicationPermissions'
        description 'Check permissions for the current user on a continuous deployment application.'

        # This type is only reachable via CdApplication.userPermissions, and
        # CdApplicationType already declares its own authorize_granular_token
        # (permissions: :read_cd_application), so resolving this type always
        # requires that authorization first.
        authorize_granular_token skip_reason: :parent_authorizes

        abilities :read_cd_application,
          :update_cd_application,
          :create_cd_service,
          :update_cd_service,
          :create_cd_version_set,
          :create_cd_rollout,
          :resolve_cd_rollout_gate,
          :create_cd_application_flow_definition,
          :create_cd_application_link
      end
    end
  end
end
