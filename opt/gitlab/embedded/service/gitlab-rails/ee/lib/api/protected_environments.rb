# frozen_string_literal: true

module API
  class ProtectedEnvironments < ::API::Base
    include PaginationParams

    protected_environments_tags = %w[protected_environments]
    ENVIRONMENT_ENDPOINT_REQUIREMENTS = ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS.merge(name: ::API::NO_SLASH_URL_PART_REGEX)

    feature_category :continuous_delivery
    urgency :low

    helpers do
      def has_deprecated_approval_rules_params?
        params[:required_approval_count].present? && params[:required_approval_count] > 0
      end

      params :shared_params do
        optional :user_id, type: Integer, desc: 'ID of the user to grant access to.'
        optional :group_id, type: Integer, desc: 'ID of the group to grant access to.'
        optional :group_inheritance_type,
          type: Integer,
          values: ::ProtectedEnvironments::Authorizable::GROUP_INHERITANCE_TYPE.values,
          desc: 'Whether to include inherited group membership. Use `0` for direct group membership only, or `1` to include inherited groups. Defaults to `0`.'
      end

      params :shared_update_params do
        optional :id, type: Integer, desc: 'ID of an existing entry to update.'
        optional :_destroy, type: Boolean, desc: 'If `true`, deletes the object.'
      end

      params :deploy_access_levels do
        requires :deploy_access_levels,
          as: :deploy_access_levels_attributes,
          type: Array,
          desc: 'Array of access levels allowed to deploy to the environment, with each entry specifying a user, group, or access level.' do
          use :shared_params

          # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
          optional :access_level,
            type: Integer,
            values: ::ProtectedEnvironments::DeployAccessLevel::ALLOWED_ACCESS_LEVELS,
            desc: 'Access level allowed to deploy to the environment.'
          # rubocop:enable API/AccessLevelStringType
        end
      end

      params :optional_approval_rules do
        optional :approval_rules,
          as: :approval_rules_attributes,
          type: Array,
          desc: 'Array of access levels allowed to approve deployments to the environment, with each entry specifying a user, group, or access level. Use `required_approvals` to set the number of approvals required from each entry.' do
          use :shared_params
          use :shared_update_params

          # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
          optional :access_level,
            type: Integer,
            values: ::ProtectedEnvironments::ApprovalRule::ALLOWED_ACCESS_LEVELS,
            desc: 'Access level allowed to approve deployments to the environment.'
          # rubocop:enable API/AccessLevelStringType

          optional :required_approvals,
            type: Integer,
            default: 1,
            desc: 'Number of approvals required for this rule.'

          given _destroy: ->(value) { value != true } do
            at_least_one_of :access_level, :user_id, :group_id
          end
        end
      end

      params :optional_deploy_access_levels do
        optional :deploy_access_levels, as: :deploy_access_levels_attributes, type: Array, desc: 'Array of access levels allowed to deploy to the environment, with each entry specifying a user, group, or access level.' do
          use :shared_params
          use :shared_update_params

          # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
          optional :access_level,
            type: Integer,
            values: ::ProtectedEnvironments::DeployAccessLevel::ALLOWED_ACCESS_LEVELS,
            desc: 'Access level allowed to deploy to the environment.'
          # rubocop:enable API/AccessLevelStringType
        end
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      helpers do
        def protected_environment
          @protected_environment ||= user_project.protected_environments.find_by_name!(params[:name])
        end
      end

      before { authorize! :admin_protected_environments, user_project }

      desc 'List all protected environments for a project' do
        detail 'Lists all protected environments for a specified project.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '404', message: 'Not found' }
        ]
        is_array true
        tags protected_environments_tags
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_protected_environment, boundary_type: :project
      get ':id/protected_environments' do
        protected_environments = user_project.protected_environments.sorted_by_name

        present paginate(protected_environments), with: ::API::Entities::ProtectedEnvironment, project: user_project
      end

      desc 'Retrieve a protected environment for a project' do
        detail 'Retrieves a specified protected environment for a project.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '404', message: 'Not found' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name, type: String, desc: 'Name of the protected environment.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_protected_environment, boundary_type: :project
      get ':id/protected_environments/:name', requirements: ENVIRONMENT_ENDPOINT_REQUIREMENTS do
        present protected_environment, with: ::API::Entities::ProtectedEnvironment, project: user_project
      end

      desc 'Protect an environment for a project' do
        detail 'Protects a specified environment for a project. Each `user_id` must belong to a user with at least the ' \
          'Developer role for the project. Each `group_id` must belong to a group the project is shared with.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '409', message: 'Conflict' },
          { code: '404', message: 'Not found' },
          { code: '422', message: 'Unprocessable entity' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name, type: String, desc: 'Name of the environment.'
        optional :required_approval_count, type: Integer, desc: 'Number of approvals required to deploy to the environment. Values greater than `0` are rejected. Deprecated. Use `approval_rules` instead.', default: 0

        use :deploy_access_levels
        use :optional_approval_rules
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_protected_environment, boundary_type: :project
      post ':id/protected_environments' do
        if has_deprecated_approval_rules_params?
          unprocessable_entity!(s_("ProtectedEnvironment|Parameter 'required_approval_count' is deprecated and shouldn't be used. See https://gitlab.com/groups/gitlab-org/-/epics/9662"))
        end

        protected_environment = user_project.protected_environments.find_by_name(params[:name])

        if protected_environment
          conflict!(format(s_("ProtectedEnvironment|Environment '%{environment_name}' is already protected"), environment_name: params[:name]))
        end

        declared_params = declared_params(include_missing: false)
        protected_environment = ::ProtectedEnvironments::CreateService
                                  .new(container: user_project, current_user: current_user, params: declared_params).execute

        if protected_environment.persisted?
          present protected_environment, with: ::API::Entities::ProtectedEnvironment, project: user_project
        else
          render_api_error!(protected_environment.errors.full_messages, 422)
        end
      end

      desc 'Update a protected environment for a project' do
        detail 'Updates a specified protected environment for a project. Each `user_id` must belong to a user with at ' \
          'least the Developer role for the project. Each `group_id` must belong to a group the project is shared ' \
          'with. To update an existing entry, pass its `id` in the `deploy_access_levels` or `approval_rules` hash.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '404', message: 'Not found' },
          { code: '422', message: 'Unprocessable entity' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name, type: String, desc: 'Name of the environment.'
        optional :required_approval_count, type: Integer, desc: 'Number of approvals required to deploy to the environment. Values greater than `0` are rejected. Deprecated. Use `approval_rules` instead.'

        use :optional_deploy_access_levels
        use :optional_approval_rules
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :update_protected_environment, boundary_type: :project
      put ':id/protected_environments/:name', requirements: ENVIRONMENT_ENDPOINT_REQUIREMENTS do
        not_found! unless protected_environment

        if has_deprecated_approval_rules_params?
          unprocessable_entity!(s_("ProtectedEnvironment|Parameter 'required_approval_count' is deprecated and shouldn't be used. See https://gitlab.com/groups/gitlab-org/-/epics/9662"))
        end

        declared_params = declared_params(include_missing: false)

        result = ::ProtectedEnvironments::UpdateService
                   .new(container: user_project, current_user: current_user, params: declared_params)
                   .execute(protected_environment)

        if result
          present protected_environment, with: ::API::Entities::ProtectedEnvironment, project: user_project
        else
          render_api_error!(protected_environment.errors.full_messages, 422)
        end
      end

      desc 'Unprotect a protected environment for a project' do
        detail 'Unprotects a specified protected environment for a project.'
        success code: 204, message: 'Resource deleted'
        tags protected_environments_tags
      end
      params do
        requires :name, type: String, desc: 'Name of the protected environment.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_protected_environment, boundary_type: :project
      delete ':id/protected_environments/:name', requirements: ENVIRONMENT_ENDPOINT_REQUIREMENTS do
        destroy_conditionally!(protected_environment) do
          ::ProtectedEnvironments::DestroyService.new(container: user_project, current_user: current_user).execute(protected_environment)
        end
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of a group maintained by the authenticated user.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      helpers do
        def protected_environment
          @protected_environment ||= user_group.protected_environments.find_by_name!(params[:name])
        end
      end

      before do
        authorize! :admin_protected_environments, user_group
      end

      desc 'List all protected environments for a group' do
        detail 'Lists all protected environments for a specified group.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '404', message: 'Not found' }
        ]
        is_array true
        tags protected_environments_tags
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_protected_environment, boundary_type: :group
      get ':id/protected_environments' do
        protected_environments = user_group.protected_environments.sorted_by_name

        present paginate(protected_environments), with: ::API::Entities::ProtectedEnvironment
      end

      desc 'Retrieve a protected environment for a group' do
        detail 'Retrieves a specified protected environment for a group.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '400', message: 'Bad request' },
          { code: '404', message: 'Not found' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name,
          type: String,
          values: ::Environment.tiers.keys,
          desc: 'The deployment tier of the protected environment.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_protected_environment, boundary_type: :group
      get ':id/protected_environments/:name' do
        present protected_environment, with: ::API::Entities::ProtectedEnvironment
      end

      desc 'Protect an environment for a group' do
        detail 'Protects a specified environment for a group. Each `user_id` must belong to a user with at least the ' \
          'Maintainer role for the group. Each `group_id` must belong to the group, one of its subgroups, or a ' \
          'group it is shared with.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '400', message: 'Bad request' },
          { code: '409', message: 'Conflict' },
          { code: '404', message: 'Not found' },
          { code: '422', message: 'Unprocessable entity' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name,
          type: String,
          values: ::Environment.tiers.keys,
          desc: 'The deployment tier of the protected environment.'

        optional :required_approval_count,
          type: Integer,
          desc: 'Number of approvals required to deploy to the environment. Values greater than `0` are rejected. Deprecated. Use `approval_rules` instead.',
          default: 0

        use :deploy_access_levels
        use :optional_approval_rules
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_protected_environment, boundary_type: :group
      post ':id/protected_environments' do
        if has_deprecated_approval_rules_params?
          unprocessable_entity!(s_("ProtectedEnvironment|Parameter 'required_approval_count' is deprecated and shouldn't be used. See https://gitlab.com/groups/gitlab-org/-/epics/9662"))
        end

        protected_environment = user_group.protected_environments.find_by_name(params[:name])

        if protected_environment
          conflict!("Protected environment '#{params[:name]}' already exists")
        end

        declared_params = declared_params(include_missing: false)
        protected_environment = ::ProtectedEnvironments::CreateService
                                  .new(container: user_group, current_user: current_user, params: declared_params).execute

        if protected_environment.persisted?
          present protected_environment, with: ::API::Entities::ProtectedEnvironment
        else
          render_api_error!(protected_environment.errors.full_messages, 422)
        end
      end

      desc 'Update a protected environment for a group' do
        detail 'Updates a specified protected environment for a group. Each `user_id` must belong to a user with at ' \
          'least the Maintainer role for the group. Each `group_id` must belong to the group, one of its ' \
          'subgroups, or a group it is shared with. To update an existing entry, pass its `id` in the ' \
          '`deploy_access_levels` or `approval_rules` hash.'
        success ::API::Entities::ProtectedEnvironment
        failure [
          { code: '400', message: 'Bad request' },
          { code: '404', message: 'Not found' },
          { code: '422', message: 'Unprocessable entity' }
        ]
        tags protected_environments_tags
      end
      params do
        requires :name,
          type: String,
          values: ::Environment.tiers.keys,
          desc: 'The deployment tier of the protected environment.'

        optional :required_approval_count,
          type: Integer,
          desc: 'Number of approvals required to deploy to the environment. Values greater than `0` are rejected. Deprecated. Use `approval_rules` instead.',
          default: 0

        use :optional_deploy_access_levels
        use :optional_approval_rules
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :update_protected_environment, boundary_type: :group
      put ':id/protected_environments/:name' do
        not_found! unless protected_environment

        if has_deprecated_approval_rules_params?
          unprocessable_entity!(s_("ProtectedEnvironment|Parameter 'required_approval_count' is deprecated and shouldn't be used. See https://gitlab.com/groups/gitlab-org/-/epics/9662"))
        end

        declared_params = declared_params(include_missing: false)

        result = ::ProtectedEnvironments::UpdateService
                   .new(container: user_group, current_user: current_user, params: declared_params)
                   .execute(protected_environment)

        if result
          present protected_environment, with: ::API::Entities::ProtectedEnvironment, project: user_group
        else
          render_api_error!(protected_environment.errors.full_messages, 422)
        end
      end

      desc 'Unprotect a group environment' do
        detail 'Unprotects a specified protected environment for a group.'
        success code: 204, message: 'Resource deleted'
        tags protected_environments_tags
      end
      params do
        requires :name, type: String, desc: '[Deployment tier](https://docs.gitlab.com/ci/environments/#deployment-tier-of-environments) of the protected environment. Possible values are `production`, `staging`, `testing`, `development`, and `other`.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_protected_environment, boundary_type: :group
      delete ':id/protected_environments/:name' do
        destroy_conditionally!(protected_environment) do
          ::ProtectedEnvironments::DestroyService.new(container: user_group, current_user: current_user).execute(protected_environment)
        end
      end
    end
  end
end
