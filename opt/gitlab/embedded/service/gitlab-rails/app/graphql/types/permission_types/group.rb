# frozen_string_literal: true

module Types
  module PermissionTypes
    class Group < BasePermissionType
      graphql_name 'GroupPermissions'

      authorize_granular_token parent_authorizes: :read_group

      abilities(
        :read_group,
        :change_group,
        :create_projects,
        :create_custom_emoji,
        :remove_group,
        :view_edit_page,
        :admin_issue,
        :read_crm_contact,
        :read_crm_organization,
        :archive_group
      )

      permission_field :can_leave,
        description: 'If `true`, the user can leave this group.'

      permission_field :admin_all_resources,
        description: 'If `true`, the user is an instance administrator.'

      def can_leave
        return false unless current_user

        Ability.allowed?(current_user, :destroy_group_member, object.member(current_user))
      end

      def admin_all_resources
        return false unless current_user

        current_user.can_admin_all_resources?
      end
    end
  end
end

::Types::PermissionTypes::Group.prepend_mod
