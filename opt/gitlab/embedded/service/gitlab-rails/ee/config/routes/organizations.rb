# frozen_string_literal: true

# Skip creating organization scoped versions of these
# See https://gitlab.com/gitlab-org/gitlab/-/blob/d2272513eabc62b1342e4d9f0d775f7c1764eae0/config/routes.rb#L412
unless @organization_scoped_routes
  resources(
    :organizations,
    path: 'o',
    param: :organization_path,
    constraints: {
      organization_path: Gitlab::PathRegex.organization_route_regex
    },
    only: [],
    module: :organizations
  ) do
    member do
      scope(path: '-') do
        get :access, to: 'access#index', as: :access, format: false
        get 'access/artifact-registry', to: 'access#artifact_registry', as: :artifact_registry_access, format: false

        resources :artifact_registry, only: [:index], as: :artifact_registry_organization

        get 'artifact_registry/:slug/repositories(/*vueroute)',
          to: 'artifact_registry_repositories#index',
          as: :artifact_registry_repositories,
          format: false

        get 'artifact_registry/:slug/trash',
          to: 'artifact_registry_repositories#trash',
          as: :artifact_registry_trash,
          format: false

        get :gitlab_credits_dashboard, to: 'gitlab_credits_dashboard#show', format: false

        resource :settings, only: [], as: :settings_organization do
          get :artifact_registry, to: 'settings/artifact_registry#show', format: false
        end

        # `namespace :security` would steal the `security_dashboard` route name from the instance
        # dashboard, whose organization-scoped clone this path also deliberately shadows.
        get 'security/dashboard', to: 'security/dashboard#show', as: :security_dashboard, format: false

        get 'security/policy_store', to: 'security/policy_store#index', as: :security_policy_store,
          format: false
        get 'security/policy_store/new', to: 'security/policy_store#new', as: :new_security_policy_store,
          format: false
        get 'security/policy_store/:id', to: 'security/policy_store#show',
          as: :security_policy_store_policy, format: false, constraints: { id: /\d+/ }
        get 'security/policy_store/:id/edit', to: 'security/policy_store#edit',
          as: :edit_security_policy_store, format: false, constraints: { id: /\d+/ }

        scope :deploy do
          get '/(*vueroute)' => 'continuous_deployment#show', as: :deploy, format: false
          get 'applications', to: 'continuous_deployment#show', as: :deploy_applications, format: false
          get 'environments', to: 'continuous_deployment#show', as: :deploy_environments, format: false
        end
      end
    end
  end
end
