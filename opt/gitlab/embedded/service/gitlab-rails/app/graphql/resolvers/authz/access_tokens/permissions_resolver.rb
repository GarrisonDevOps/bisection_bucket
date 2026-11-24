# frozen_string_literal: true

module Resolvers
  module Authz
    module AccessTokens
      class PermissionsResolver < BaseResolver
        type [Types::Authz::AccessTokens::PermissionType], null: false

        def resolve
          # sorting categories and resources case-insensitively by display name.
          assignable_permissions.sort_by do |permission|
            [
              permission.category_name.to_s.downcase,
              permission.category_name.to_s,
              permission.resource_name.to_s.downcase,
              permission.resource_name.to_s,
              permission.action.to_s
            ]
          end
        end

        private

        def assignable_permissions
          ::Authz::PermissionGroups::Assignable.available_definitions.filter_map do |permission|
            boundaries = permission.assignable_boundaries_for(current_user)
            next if boundaries.empty?

            ::Authz::PermissionGroups::FilteredAssignable.new(permission, boundaries: boundaries)
          end
        end
      end
    end
  end
end
