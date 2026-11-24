# frozen_string_literal: true

module API
  class Organizations < ::API::Base
    feature_category :organization

    before { authenticate! }

    helpers do
      def authorize_organization_creation!
        authorize! :create_organization
      end
    end

    resource :organizations do
      desc 'Create an organization' do
        detail 'Creates an organization. This feature was introduced in GitLab 17.5. ' \
          'This feature is behind the `allow_organization_creation` feature flag. ' \
          'In GitLab 18.3, the feature flag changed to `organization_switching`. ' \
          'In GitLab 19.4, the feature flag changed to `org_stage_experimental`.'
        success Entities::Organizations::Organization
        tags %w[organizations]
      end
      params do
        requires :name, type: String, desc: 'The name of the organization'
        requires :path, type: String, desc: 'The path of the organization'
        optional :description, type: String, desc: 'The description of the organization'
        optional :visibility, type: String,
          values: %w[private public],
          desc: 'The visibility level of the organization'
        optional :avatar, type: ::API::Validations::Types::WorkhorseFile, desc: 'The avatar image for the organization',
          documentation: { type: 'file' }
      end
      route_setting :lifecycle, :experiment
      route_setting :authorization, permissions: :create_organization, boundary_type: :instance,
        assignable_when: [:saas]
      post do
        forbidden! unless ::Organizations::Release.enabled?(:org_creation, current_user)
        check_rate_limit!(:create_organization_api, scope: { user: current_user })
        authorize_organization_creation!

        response = ::Organizations::CreateService
          .new(current_user: current_user, params: declared_params(include_missing: false))
          .execute

        if response.success?
          present response[:organization], with: Entities::Organizations::Organization
        else
          render_api_error!(response.message, :bad_request)
        end
      end

      desc 'Soft-delete an organization' do
        detail 'This feature was introduced in GitLab 19.2.'
        success code: 202
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[organizations]
      end
      params do
        requires :id, type: Integer, desc: 'ID of the organization.'
      end
      route_setting :lifecycle, :experiment
      route_setting :authorization, permissions: :delete_organization, boundary_type: :instance
      delete ':id' do
        organization = find_organization!(params[:id])

        response = ::Organizations::SoftDeleteService
          .new(organization, current_user: current_user)
          .execute

        if response.success?
          accepted!
        else
          render_api_error!(response.message, response.cause.access_denied? ? 403 : 400)
        end
      end

      desc 'Restore a soft-deleted organization' do
        detail 'Restores a soft-deleted organization. Administrators only. This feature was introduced in GitLab 19.6.'
        success Entities::Organizations::Organization
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[organizations]
      end
      params do
        requires :id, type: Integer, desc: 'The ID of the organization.'
      end
      route_setting :lifecycle, :experiment
      route_setting :authorization, permissions: :restore_organization, boundary_type: :instance,
        assignable_when: [:admin]
      post ':id/restore' do
        organization = find_organization!(params[:id])
        authorize! :restore_organization, organization

        response = ::Organizations::RestoreService
          .new(organization, current_user: current_user)
          .execute

        if response.success?
          present response[:organization], with: Entities::Organizations::Organization
        else
          render_api_error!(response.message, :bad_request)
        end
      end

      desc 'Transfer users to an organization' do
        detail 'Transfers ownership of users to the organization, including their personal namespaces ' \
          'and projects. All users must currently belong to the same organization. ' \
          'This is a change of ownership, not organization membership. The transfer runs in the background. ' \
          'Administrators only. No user can be an internal user, such as the ghost user or a bot like ' \
          '`support_bot` or `admin_bot`. Service accounts and project access token bots can be transferred. ' \
          'This feature was introduced in GitLab 19.6.'
        success code: 202
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[organizations]
      end
      params do
        requires :id, type: Integer, desc: 'The ID of the organization to transfer the users to.'
        requires :user_ids, type: Array[Integer], allow_blank: false,
          limit: ::Organizations::Transfer::UsersService::BATCH_SIZE,
          desc: "The IDs of the users to transfer. Maximum #{::Organizations::Transfer::UsersService::BATCH_SIZE}."
      end
      route_setting :lifecycle, :experiment
      route_setting :authorization, permissions: :transfer_user, boundary_type: :instance,
        assignable_when: [:admin]
      post ':id/transfer_users' do
        organization = find_organization!(params[:id])
        authorize! :transfer_user, organization

        user_ids = params[:user_ids].compact.uniq
        bad_request!('user_ids is empty') if user_ids.empty?

        users = ::User.id_in(user_ids)
        not_found!('Users') if users.count != user_ids.size

        response = ::Organizations::Transfer::UsersService
          .new(users: users, new_organization: organization)
          .async_execute

        if response.success?
          status :accepted
          { organization_id: organization.id, user_ids: user_ids }
        else
          render_api_error!(response.message, :bad_request)
        end
      end

      route_param :id, type: Integer, desc: 'The ID of the organization.' do
        resource :users do
          desc 'List organization users' do
            detail 'Lists the users of an organization. Uses keyset pagination. ' \
              'This feature was introduced in GitLab 19.6.'
            is_array true
            success Entities::Organizations::OrganizationUser
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[organizations]
          end
          params do
            optional :pagination, type: String, values: %w[keyset], default: 'keyset',
              desc: 'Pagination method. Only `keyset` is supported.'
            optional :cursor, type: String, desc: 'Cursor for obtaining the next set of records.'
            optional :order_by, type: String, values: %w[id], default: 'id',
              desc: 'Sort results by the specified field.'
            optional :sort, type: String, values: %w[asc desc], default: 'asc',
              desc: 'Sort results in ascending or descending order.'
            optional :per_page, type: Integer, values: 1..100, default: 20,
              desc: 'Number of items to list per page.'
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization, permissions: :read_organization_user, boundary_type: :instance
          get do
            check_rate_limit!(:organization_user_list, scope: { user: current_user })

            organization = find_organization!(params[:id])
            authorize! :read_organization_user, organization

            # rubocop:disable CodeReuse/ActiveRecord -- preload and ordering are specific to this endpoint
            organization_users = organization.organization_users
              .preload(:user)
              .reorder(params[:order_by] => params[:sort])
            # rubocop:enable CodeReuse/ActiveRecord

            present paginate_with_strategies(organization_users), with: Entities::Organizations::OrganizationUser
          end

          desc 'Add a user to an organization' do
            detail 'Adds a user to an organization, optionally as an owner. ' \
              'This feature was introduced in GitLab 19.6.'
            success Entities::Organizations::OrganizationUser
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[organizations]
          end
          params do
            requires :username, type: String, desc: 'The username of the user to add.'
            optional :access_level, type: String, values: %w[default owner], default: 'default',
              desc: 'The access level of the user in the organization.'
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization, permissions: :create_organization_user, boundary_type: :instance
          post do
            check_rate_limit!(:organization_user_create, scope: { user: current_user })

            organization = find_organization!(params[:id])
            authorize! :create_organization_user, organization.organization_users.new

            response = ::Organizations::OrganizationUsers::CreateService.new(
              organization,
              current_user: current_user,
              params: { username: params[:username], user_type: params[:access_level] }
            ).execute

            if response.success?
              present response[:organization_user], with: Entities::Organizations::OrganizationUser
            else
              render_api_error!(response.message.to_sentence, :bad_request)
            end
          end

          desc 'Update an organization user' do
            detail 'Changes the access level of a user in an organization, for example to promote them to owner. ' \
              'This feature was introduced in GitLab 19.6.'
            success Entities::Organizations::OrganizationUser
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[organizations]
          end
          params do
            requires :user_id, type: Integer, desc: 'The ID of the user to update.'
            requires :access_level, type: String, values: %w[default owner],
              desc: 'The access level of the user in the organization.'
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization, permissions: :update_organization_user, boundary_type: :instance
          put ':user_id' do
            check_rate_limit!(:organization_user_update, scope: { user: current_user })

            organization = find_organization!(params[:id])

            # Authorize before looking up the target so a 404 can't reveal who is a member. This matches
            # UpdateService and the GraphQL mutation, and the model blocks demoting the last owner.
            authorize! :update_organization, organization

            organization_user = organization.organization_users.find_by_user_id(params[:user_id])
            not_found!('Organization user') unless organization_user

            response = ::Organizations::OrganizationUsers::UpdateService.new(
              organization_user,
              current_user: current_user,
              params: { access_level: params[:access_level] }
            ).execute

            if response.success?
              present response[:organization_user], with: Entities::Organizations::OrganizationUser
            else
              render_api_error!(response.message.to_sentence, :bad_request)
            end
          end

          desc 'Remove a user from an organization' do
            detail 'Removes a user from an organization, including their group and project memberships in it. ' \
              'The last owner of an organization cannot be removed. ' \
              'This feature was introduced in GitLab 19.6.'
            success code: 204
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[organizations]
          end
          params do
            requires :user_id, type: Integer, desc: 'The ID of the user to remove.'
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization, permissions: :delete_organization_user, boundary_type: :instance
          delete ':user_id' do
            check_rate_limit!(:organization_user_delete, scope: { user: current_user })

            organization = find_organization!(params[:id])

            # Authorize before looking up the target so a 404 can't reveal who is a member. Members can
            # still remove themselves, which DestroyService allows without organization-level permission.
            unless params[:user_id] == current_user.id
              authorize! :delete_organization_user, organization.organization_users.new
            end

            organization_user = organization.organization_users.find_by_user_id(params[:user_id])
            not_found!('Organization user') unless organization_user

            response = ::Organizations::OrganizationUsers::DestroyService
              .new(organization_user, current_user: current_user)
              .execute

            if response.success?
              no_content!
            else
              render_api_error!(response.message.to_sentence, response.reason == :forbidden ? :forbidden : :bad_request)
            end
          end
        end
      end
    end
  end
end
