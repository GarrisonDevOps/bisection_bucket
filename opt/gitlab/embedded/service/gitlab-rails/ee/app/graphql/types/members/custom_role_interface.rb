# frozen_string_literal: true

module Types
  module Members
    # Interface for custom roles that can be created, edited, and deleted.
    module CustomRoleInterface
      include BaseInterface
      include MemberRolesHelper

      field :edit_path,
        GraphQL::Types::String,
        null: false,
        experiment: { milestone: '16.11' },
        description: 'Web UI path to edit the custom role.'

      field :created_at,
        Types::TimeType,
        null: false,
        description: 'Timestamp of when the member role was created.'

      def edit_path
        member_role_edit_path(object)
      end
    end
  end
end
