# frozen_string_literal: true

module API
  class AdminMemberRoles < ::API::Base
    before { authenticate! }

    feature_category :permissions

    helpers ::API::Helpers::MemberRolesHelpers

    DEFAULT_NAME = "Admin role - custom"

    helpers do
      include ::Gitlab::Utils::StrongMemoize

      def member_role_name
        declared_params[:name].presence || DEFAULT_NAME
      end

      def authorize_access_roles!
        authorize_admin_member_role_on_instance!
      end

      def member_roles
        ::Members::AdminRolesFinder.new(current_user).execute
      end

      params :create_role_params do
        optional :name, type: String, desc: "Name for the role. Defaults to `#{DEFAULT_NAME}`."
        optional :description, type: String, desc: 'Description for role.'

        ::Gitlab::CustomRoles::Definition.admin.each do |permission_name, permission_params|
          optional permission_name.to_s, type: Boolean, desc: permission_params[:description], default: false
        end
      end
    end

    resource :admin_member_roles do
      desc 'Get Admin Roles for this GitLab instance' do
        detail 'Retrieves all custom admin roles configured for the instance.'
        success ::API::Entities::MemberRole
        failure [[401, 'Unauthorized']]
        is_array true
        tags %w[member_roles]
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_admin_role, boundary_type: :instance
      get do
        get_roles
      end

      desc 'Create Admin Role on the GitLab instance' do
        detail 'Creates a new custom admin role with specified permissions.'
        success ::API::Entities::MemberRole
        failure [[400, 'Bad Request'], [401, 'Unauthorized']]
        tags %w[member_roles]
      end

      params do
        use :create_role_params
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_admin_member_role, boundary_type: :instance,
        assignable_when: [:admin]
      post do
        create_role
      end

      desc 'Delete Admin Role' do
        detail 'Deletes a specific custom admin role by its ID.'
        success code: 204, message: '204 No Content'
        failure [[400, 'Bad Request'], [401, 'Unauthorized'], [404, '404 Member Role Not Found']]
        tags %w[member_roles]
      end

      params do
        requires :member_role_id, type: Integer, desc: 'ID of the member role.'
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :delete_admin_member_role, boundary_type: :instance,
        assignable_when: [:admin]
      delete ':member_role_id' do
        delete_role
      end
    end
  end
end
