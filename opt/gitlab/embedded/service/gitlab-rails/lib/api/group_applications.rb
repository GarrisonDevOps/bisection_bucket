# frozen_string_literal: true

module API
  # Group applications API
  class GroupApplications < ::API::Base
    include PaginationParams

    before do
      authenticate!
    end

    feature_category :system_access

    helpers do
      def find_group_application!
        user_group.oauth_applications.find_by_id(params[:application_id]) || not_found!('Application')
      end
    end

    params do
      requires :id, type: String, desc: 'The ID or URL-encoded path of the group'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'Create a group application' do
        detail 'Creates an OAuth application owned by the specified group. ' \
          'This feature was introduced in GitLab 19.6'
        success code: 201, model: Entities::ApplicationWithSecret
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[group_applications]
      end
      params do
        requires :name, type: String, desc: 'Name of the application.', documentation: { example: 'MyApplication' }
        requires :redirect_uri, type: String, desc: 'Redirect URI of the application.', documentation: { example: 'https://redirect.uri' }
        requires :scopes, type: String,
          desc: 'Scopes available to the application. Separate multiple scopes with a space.',
          allow_blank: false

        optional :confidential,
          type: Boolean,
          default: true,
          desc: 'If `true`, the application can securely store client credentials, such as the ' \
            'client secret. Non-confidential applications, such as native mobile apps and ' \
            'Single Page Apps might expose client credentials. If unset, defaults to `true`.'
      end
      route_setting :authorization, permissions: :create_oauth_application, boundary_type: :group
      post ':id/applications' do
        authorize! :create_oauth_application, user_group

        create_params = declared_params(include_missing: false).except(:id)

        application = ::Applications::CreateService.new(
          current_user,
          request,
          create_params.merge(owner: user_group, organization: user_group.organization)
        ).execute

        if application.persisted?
          present application, with: Entities::ApplicationWithSecret
        else
          render_validation_error! application
        end
      end

      desc 'List all group applications' do
        detail 'Lists all OAuth applications owned by a specified group.'
        success Entities::Application
        is_array true
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[group_applications]
      end
      params do
        use :pagination
      end
      route_setting :authorization, permissions: :read_oauth_application, boundary_type: :group
      get ':id/applications' do
        authorize! :read_oauth_application, user_group

        present paginate(user_group.oauth_applications), with: Entities::Application
      end

      desc 'Retrieve a group application' do
        detail 'Retrieves details of a specified OAuth application owned by a group.'
        success Entities::Application
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[group_applications]
      end
      params do
        requires :application_id, type: Integer,
          desc: 'ID of the application. Differs from the `application_id` in the response.'
      end
      route_setting :authorization, permissions: :read_oauth_application, boundary_type: :group
      get ':id/applications/:application_id' do
        authorize! :read_oauth_application, user_group

        application = find_group_application!

        present application, with: Entities::Application
      end

      desc 'Update a group application' do
        detail 'Updates a specified OAuth application owned by a group. You cannot update the `redirect_uri` and ' \
          '`confidential` attributes of an existing application. To change them, delete the application and create ' \
          'it again.'
        success Entities::Application
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[group_applications]
      end
      params do
        requires :application_id, type: Integer,
          desc: 'ID of the application. Differs from the `application_id` in the response.'
        optional :name, type: String, desc: 'Name of the application.'
        optional :scopes, type: String,
          desc: 'Scopes available to the application. Separate multiple scopes with a space.',
          allow_blank: false
      end
      route_setting :authorization, permissions: :update_oauth_application, boundary_type: :group
      put ':id/applications/:application_id' do
        authorize! :update_oauth_application, user_group

        application = find_group_application!

        update_params = declared_params(include_missing: false).except(:id, :application_id)

        application = ::Authn::Applications::UpdateService.new(
          current_user,
          request,
          application,
          update_params
        ).execute

        if application.errors.empty?
          present application, with: Entities::Application
        else
          render_validation_error! application
        end
      end

      desc 'Delete a group application' do
        detail 'Deletes a specified OAuth application owned by a group.'
        success code: 204
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[group_applications]
      end
      params do
        requires :application_id, type: Integer,
          desc: 'ID of the application. Differs from the `application_id` in the response.'
      end
      route_setting :authorization, permissions: :delete_oauth_application, boundary_type: :group
      delete ':id/applications/:application_id' do
        authorize! :delete_oauth_application, user_group

        application = find_group_application!

        result = ::Authn::Applications::DestroyService.new(
          current_user,
          request,
          application
        ).execute

        if result.destroyed?
          no_content!
        else
          render_validation_error!(result)
        end
      end
    end
  end
end
