# frozen_string_literal: true

namespace :admin do
  resource :orbit, only: [:show, :update], controller: 'orbit'

  resources :users, only: [], constraints: { id: %r{[a-zA-Z./0-9_-]+} } do
    member do
      post :identity_verification_exemption
      delete :destroy_identity_verification_exemption
      post :reset_runners_minutes
      get :card_match
      get :phone_match
    end
  end

  scope(
    path: 'groups/*id',
    controller: :groups,
    constraints: { id: Gitlab::PathRegex.full_namespace_route_regex, format: /(html|json|atom)/ }
  ) do
    scope(as: :group) do
      post :reset_runners_minutes
    end
  end

  resource :push_rule, only: [:show, :update]
  resource :email, only: [:show, :create]
  resources :audit_logs, controller: 'audit_logs', only: [:index]
  resources :audit_log_reports, only: [:index], constraints: { format: :csv }
  resources :credentials, only: [:index, :destroy] do
    resources :resources, only: [] do
      put :revoke, controller: :credentials
    end
    member do
      put :revoke
    end
  end
  resources :user_permission_exports, controller: 'user_permission_exports', only: [:index]

  resource :license, only: [:show, :create, :destroy] do
    get :download, on: :member
    post :sync_seat_link, on: :collection

    resource :usage_export, controller: 'licenses/usage_exports', only: [:show]
    resource :billable_usage_export, controller: 'licenses/billable_usage_exports', only: [:show] do
      get :download
      get :terms
    end
  end

  resource :subscription, only: [:show] do
    get :billable_usage
  end
  resources :role_promotion_requests, only: :index

  resource :discover_premium, only: [:show]

  resource :gitlab_duo, only: [:show], controller: 'gitlab_duo'
  namespace :gitlab_duo do
    resources :seat_utilization, only: [:index]
    resources :configuration, only: [:index]
    resources :model_selection, only: [:index]

    get 'model_selection(/*vueroute)', to: 'model_selection#index'
  end
  get '/code_suggestions', to: redirect('admin/gitlab_duo/seat_utilization')
  resources :gitlab_credits_dashboard, only: [:index]
  scope '/gitlab_credits_dashboard' do
    resources :users, only: [:show], controller: 'gitlab_credits_dashboard/users', param: :username,
      as: :gitlab_credits_dashboard_users, format: false,
      constraints: { username: Gitlab::PathRegex.root_namespace_route_regex }
    resources :credit_caps, only: [:index], controller: 'gitlab_credits_dashboard/credit_caps',
      as: :gitlab_credits_dashboard_credit_caps
  end

  namespace :ai do
    post 'duo_self_hosted/toggle_beta_models', to: 'terms_and_conditions#toggle_beta_models'

    resources :duo_workflow_settings, only: [:create] do
      collection do
        post :disconnect
      end
    end

    resources :amazon_q_settings, only: [:index, :create] do
      collection do
        post :disconnect
      end
    end
  end

  # using `only: []` to keep duplicate routes from being created
  resource :application_settings, only: [] do
    get :seat_link_payload
    match :templates, via: [:get, :patch]
    match :search, via: [:get, :patch]
    get 'search/vector_storage', to: '/search/admin/vector_storage#show', as: :search_vector_storage
    match :security_and_compliance, via: [:get, :patch]
    match :namespace_storage, via: [:get, :patch]
    get :work_item
    get :advanced_search, to: redirect('admin/application_settings/search')
    get :geo, to: "geo/settings#show"
    put :update_microsoft_application
    resource :slack, only: [] do
      put :duo_group
    end

    resource :scim_oauth, only: [:create], controller: :scim_oauth, module: 'application_settings'

    resources :roles_and_permissions, only: [:index, :new, :edit, :show], module: 'application_settings'
    resources :semantic_search_embeddings, only: [:show, :update],
      path: 'search/semantic_search_embeddings',
      controller: '/search/admin/semantic_search_embeddings' do
      member do
        post :test_model_configuration
        put :update_embeddings_request_batch_size
      end
    end
  end

  namespace :geo do
    get '/' => 'nodes#index'

    resources :nodes, path: 'sites', only: [:index, :create, :new, :edit, :update] do
      member do
        scope '/replication' do
          get '/', to: 'nodes#index'
          get '/:replicable_name_plural', to: 'replicables#index', as: 'site_replicables'
          get '/:replicable_name_plural/:replicable_id', to: 'replicables#show', as: 'replicable_details'
        end
      end
    end

    scope '/replication' do
      get '/', to: redirect(path: 'admin/geo/sites')
      get '/:replicable_name_plural', to: 'replicables#index', as: 'replicables'
    end

    resource :settings, only: [:show, :update]
  end

  namespace :elasticsearch do
    post :enqueue_index
    post :trigger_reindexing
    post :cancel_index_deletion
    post :retry_migration
  end

  scope '/search/vector_storage', as: :search_vector_storage,
    controller: '/search/admin/vector_storage' do
    post :use_advanced_search_cluster_for_semantic_search
    post :connect_custom_elasticsearch_vector_storage, defaults: { adapter: 'elasticsearch' }
    post :connect_custom_opensearch_vector_storage, defaults: { adapter: 'opensearch' }
    post :connect_custom_postgresql_vector_storage, defaults: { adapter: 'postgresql' }
    post :disable_semantic_search
  end

  get 'namespace_limits', to: 'namespace_limits#index'
  get 'namespace_limits/export_usage', to: 'namespace_limits#export_usage'

  resources :runners, only: [] do
    collection do
      get :dashboard
    end
  end

  resources :targeted_messages, only: [:index, :new, :create, :edit, :update, :destroy]

  resource :minimal_access_provisioning_alert_dismissal, only: :create,
    controller: 'minimal_access_provisioning_alert_dismissals'

  resource :data_management do
    get '/', to: 'data_management#index'
    get '/:model_name', to: 'data_management#index', as: 'list'
    get '/:model_name/:id', to: 'data_management#show', as: 'details'
  end
end
