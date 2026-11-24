# frozen_string_literal: true

module API
  class MemberRoles < ::API::Base
    before { authenticate! }

    feature_category :system_access

    helpers ::API::Helpers::MemberRolesHelpers

    helpers do
      include ::Gitlab::Utils::StrongMemoize

      def member_role_name
        declared_params[:name].presence || "#{Gitlab::Access.human_access(params[:base_access_level])} - custom"
      end

      def authorize_access_roles!
        return authorize_admin_member_role_on_group! if params[:id]

        authorize_admin_member_role_on_instance!
      end

      def group
        return unless params[:id]

        user_group
      end
      strong_memoize_attr :group

      def member_roles
        filter_params = group ? { parent: group } : {}

        ::MemberRoles::RolesFinder.new(current_user, filter_params).execute
      end

      params :create_role_params do
        # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
        requires 'base_access_level', type: Integer, values: Gitlab::Access.all_values,
          desc: 'Base access level for the custom role.', documentation: { example: 10 }
        # rubocop:enable API/AccessLevelStringType

        optional :name, type: String, desc: 'Name of the custom role. Defaults to `<base access level> - custom`, ' \
                                        'for example `Developer - custom`.'
        optional :description, type: String, desc: 'Description of the custom role.'

        ::MemberRole.all_customizable_permissions.each do |permission_name, permission_params|
          optional permission_name.to_s, type: Boolean, desc: permission_params[:description], default: false
        end
      end

      def deprecation_message
        docs_page = Rails.application.routes.url_helpers.help_page_url(
          'update/deprecations.md',
          anchor: 'deprecate-custom-role-creation-for-group-owners-on-self-managed'
        )

        "Group-level custom roles are deprecated on self-managed instances. " \
          "See #{docs_page}"
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end

    resource :groups do
      before do
        bad_request!(deprecation_message) unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      desc 'List all group member roles' do
        detail 'Lists all member roles in a specified group.'
        success ::API::Entities::MemberRole
        is_array true
        tags %w[member_roles]
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_member_role, boundary_type: :group, assignable_when: [:saas]
      get ":id/member_roles" do
        get_roles
      end

      desc 'Add a member role to a group' do
        detail 'Adds a member role to a group. You can only add member roles at the root level of the group.'
        success ::API::Entities::MemberRole
        failure [[400, 'Bad Request'], [401, 'Unauthorized']]
        tags %w[member_roles]
      end

      params do
        use :create_role_params
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_member_role, boundary_type: :group, assignable_when: [:saas]
      post ":id/member_roles" do
        create_role
      end

      desc 'Remove member role of a group' do
        detail 'Removes a specified member role from a group.'
        success code: 204, message: '204 No Content'
        failure [[400, 'Bad Request'], [401, 'Unauthorized'], [404, '404 Member Role Not Found']]
        tags %w[member_roles]
      end

      params do
        requires :member_role_id, type: Integer, desc: 'ID of the member role.'
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :delete_member_role, boundary_type: :group, assignable_when: [:saas]
      delete ":id/member_roles/:member_role_id" do
        delete_role
      end
    end

    resource :member_roles do
      before do
        bad_request! if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      desc 'List all instance member roles' do
        detail 'Lists all member roles for this GitLab instance.'
        success ::API::Entities::MemberRole
        failure [[401, 'Unauthorized']]
        is_array true
        tags %w[member_roles]
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_member_role, boundary_type: :instance,
        assignable_when: [:self_managed]
      get do
        get_roles
      end

      desc 'Create an instance member role' do
        detail 'Creates an instance member role.'
        success ::API::Entities::MemberRole
        failure [[400, 'Bad Request'], [401, 'Unauthorized']]
        tags %w[member_roles]
      end

      params do
        use :create_role_params
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_member_role, boundary_type: :instance,
        assignable_when: [:admin, :self_managed]
      post do
        create_role
      end

      desc 'Delete an instance member role' do
        detail 'Deletes an instance member role.'
        success code: 204, message: '204 No Content'
        failure [[400, 'Bad Request'], [401, 'Unauthorized'], [404, '404 Member Role Not Found']]
        tags %w[member_roles]
      end

      params do
        requires :member_role_id, type: Integer, desc: 'ID of the member role.'
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :delete_member_role, boundary_type: :instance,
        assignable_when: [:admin, :self_managed]
      delete ':member_role_id' do
        delete_role
      end
    end
  end
end
