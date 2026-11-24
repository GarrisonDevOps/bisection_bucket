# frozen_string_literal: true

module Types
  module PermissionTypes
    module Notes
      class Discussion < BasePermissionType
        graphql_name 'DiscussionPermissions'

        authorize_granular_token parent_authorizes: :read_note

        permission_field :resolve_note

        def resolve_note
          object.can_resolve?(context[:current_user])
        end
      end
    end
  end
end
