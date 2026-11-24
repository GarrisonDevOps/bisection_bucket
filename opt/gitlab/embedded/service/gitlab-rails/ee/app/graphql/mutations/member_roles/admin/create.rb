# frozen_string_literal: true

module Mutations
  module MemberRoles
    module Admin
      class Create < Base
        graphql_name 'MemberRoleAdminCreate'

        authorize :create_admin_role
        authorize_granular_token permissions: :create_admin_member_role, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        def resolve(**args)
          params = canonicalize_for_create(args)
          response = ::MemberRoles::CreateService.new(current_user, params).execute

          raise_resource_not_available_error! if response.error? && response.reason == :unauthorized

          {
            member_role: response.payload,
            errors: response.errors
          }
        end
      end
    end
  end
end
