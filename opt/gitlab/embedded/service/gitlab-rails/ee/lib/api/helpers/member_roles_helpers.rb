# frozen_string_literal: true

module API
  module Helpers
    module MemberRolesHelpers
      include ::Gitlab::Utils::StrongMemoize

      def member_role
        return group.member_roles.find_by_id(params[:member_role_id]) if group

        MemberRole.find_by_id(params[:member_role_id])
      end
      strong_memoize_attr :member_role

      def get_roles
        if params[:id]
          authorize! :read_member_role, user_group
        else
          authorize_admin_member_role_on_instance!
        end

        present member_roles, with: ::API::Entities::MemberRole
      end

      def group
        nil
      end

      def create_role
        authorize_access_roles!

        name = member_role_name
        create_params = declared_params.merge(name: name, namespace: group).compact

        service = ::MemberRoles::CreateService.new(current_user, create_params)
        response = service.execute

        if response.success?
          present response.payload, with: ::API::Entities::MemberRole
        else
          render_api_error!(response.message, 400)
        end
      end

      def delete_role
        authorize_access_roles!

        not_found!('Member Role') unless member_role

        response = ::MemberRoles::DeleteService.new(current_user).execute(member_role)

        if response.success?
          no_content!
        else
          render_api_error!(response.message, 400)
        end
      end
    end
  end
end
