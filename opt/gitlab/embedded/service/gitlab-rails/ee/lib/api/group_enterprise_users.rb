# frozen_string_literal: true

module API
  class GroupEnterpriseUsers < ::API::Base
    include PaginationParams

    feature_category :user_management

    helpers Gitlab::InternalEventsTracking

    helpers do
      def track_get_group_enterprise_users_api
        track_internal_event(
          'use_get_group_enterprise_users_api',
          user: current_user,
          namespace: user_group
        )
      end
    end

    before do
      authenticate!
      bad_request!('Must be a top-level group') unless user_group.root?
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all enterprise users' do
        detail 'Lists all enterprise users for a specified top-level group. Use the `page` and `per_page` pagination ' \
          'parameters to filter the results.'
        success ::API::Entities::UserPublic
        is_array true
        tags ['enterprise_users']
      end
      params do
        optional :username, type: String, desc: 'Return a user with the given username.'
        optional :search, type: String, desc: 'Return users with a matching name, email, or username. Use partial ' \
                                          'values to increase results.'
        optional :active, type: Grape::API::Boolean, default: false, desc: 'If `true`, returns only active users.'
        optional :blocked, type: Grape::API::Boolean, default: false, desc: 'If `true`, returns only blocked users.'
        optional :created_after, type: DateTime, desc: 'Return users created on or after the specified time.'
        optional :created_before, type: DateTime, desc: 'Return users created on or before the specified time.'
        optional(
          :two_factor,
          type: String,
          desc: 'Filter users by two-factor authentication (2FA). ' \
            'Filter values are `enabled` or `disabled`. By default it returns all users.'
        )

        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_enterprise_user, boundary_type: :group
      get ':id/enterprise_users' do
        authorize! :read_enterprise_user, user_group

        finder = ::Authn::EnterpriseUsersFinder.new(
          current_user,
          declared_params.merge(enterprise_group: user_group))

        users = finder.execute.preload(:identities, :group_scim_identities, :instance_scim_identities) # rubocop: disable CodeReuse/ActiveRecord -- preload

        track_get_group_enterprise_users_api

        present paginate(users), with: ::API::Entities::UserPublic
      end

      desc 'Retrieve an enterprise user' do
        detail 'Retrieves a specified enterprise user.'
        success ::API::Entities::UserPublic
        tags ['enterprise_users']
      end
      params do
        requires :user_id, type: Integer, desc: 'ID of the user.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_enterprise_user, boundary_type: :group
      get ":id/enterprise_users/:user_id" do
        authorize! :read_enterprise_user, user_group

        user = user_group.enterprise_users.find(declared_params[:user_id])

        present user, with: ::API::Entities::UserPublic
      end

      desc 'Disable two-factor authentication for an enterprise user' do
        detail 'Disables two-factor authentication (2FA) for a specified enterprise user.'
        success code: 204
        tags ['enterprise_users']
      end
      params do
        requires :user_id, type: Integer, desc: 'ID of the user.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :disable_two_factor_enterprise_user, boundary_type: :group
      patch ":id/enterprise_users/:user_id/disable_two_factor" do
        authorize! :disable_two_factor_enterprise_user, user_group

        user = user_group.enterprise_users.find(declared_params[:user_id])

        result = TwoFactor::DestroyService.new(current_user, user: user, group: user_group).execute

        if result[:status] == :success
          no_content!
        else
          bad_request!(result[:message])
        end
      end

      desc 'Update an enterprise user' do
        detail 'Updates a specified enterprise user.'
        success ::API::Entities::UserPublic
        tags ['enterprise_users']
      end
      params do
        requires :user_id, type: Integer, desc: 'ID of the user.'
        optional :name, type: String, desc: 'Name of the user account.'
        optional :email, type: String,
          desc: 'Email address of the user account. Must be from a verified [group domain](https://docs.gitlab.com/user/enterprise_user/#manage-group-domains).'
        optional :projects_limit, type: Integer, values: 0.., desc: 'Maximum number of projects the user can create.'
        optional :can_create_group, type: Boolean, desc: 'If `true`, the user can create groups.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :update_enterprise_user, boundary_type: :group
      patch ":id/enterprise_users/:user_id" do
        authorize! :update_enterprise_user, user_group

        user = user_group.enterprise_users.find(declared_params[:user_id])

        result = ::Users::UpdateService.new(
          current_user,
          declared_params(include_missing: false).except(:user_id).merge(user: user, force_name_change: true)
        ).execute do |user|
          user.skip_reconfirmation! if user.enterprise_group.owner_of_email?(declared_params[:email])
        end

        if result[:status] == :success
          present user, with: ::API::Entities::UserPublic
        else
          render_api_error!(result[:message], result[:reason] || :bad_request)
        end
      end

      desc 'Delete an enterprise user' do
        detail 'Deletes a specified enterprise user.'
        success code: 204, message: 'Resource deleted'
        tags ['enterprise_users']
      end
      params do
        requires :user_id, type: Integer, desc: 'ID of the user.'
        optional :hard_delete,
          type: Grape::API::Boolean,
          default: false,
          desc: 'If `true`, deletes the user, their associated contributions, and any groups owned solely by the ' \
            'user. If `false`, deletes the user and moves their contributions to a [ghost ' \
            'user](https://docs.gitlab.com/user/profile/account/delete_account/#associated-records).'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_enterprise_user, boundary_type: :group
      delete ":id/enterprise_users/:user_id" do
        authorize! :delete_enterprise_user, user_group

        user = user_group.enterprise_users.find(declared_params[:user_id])

        authorize! :destroy_user, user

        unless user.can_be_removed? || declared_params[:hard_delete]
          conflict!('Can not remove a user who is the sole owner of a group.')
        end

        destroy_conditionally!(user) do
          user.delete_async(deleted_by: current_user, params: { hard_delete: declared_params[:hard_delete] })
        end
      end
    end
  end
end
