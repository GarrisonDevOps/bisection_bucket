# frozen_string_literal: true

constraints(::Namespaces::GroupUrlConstraint.new) do
  scope(
    path: 'groups/*group_id/-',
    module: :groups,
    as: :group,
    constraints: { group_id: Gitlab::PathRegex.full_namespace_route_regex }
  ) do
    draw :wiki

    namespace :settings do
      resource :reporting, only: [:show], controller: 'reporting'
      resources :domain_verification, only: [:index, :new, :create, :show, :update, :destroy], constraints: { id: %r{[^/]+} } do
        member do
          post :verify
          post :retry_auto_ssl
          delete :clean_certificate
        end
      end
      resources :roles_and_permissions, only: [:index, :new, :edit, :show]
      resource :analytics, only: [:show, :update]
      resource :gitlab_duo, only: [:show], controller: 'gitlab_duo'
      resource :orbit, only: [:show], controller: 'orbit'
      resource :slack, only: [] do
        get :duo_group, action: :duo_workspaces
        put :duo_group
      end
      resource :secure, only: [:show, :update], controller: 'secure' do
        patch :ai_governance
      end
      namespace :gitlab_duo do
        resources :seat_utilization, only: [:index]
        resources :configuration, only: [:index]
        resources :model_selection, only: [:index]
        get 'governance', as: nil, to: redirect { |params, request|
          path = "groups/#{params[:group_id]}/-/automate/governance"
          request.query_string.present? ? "#{path}?#{request.query_string}" : path
        }
      end

      resources :gitlab_credits_dashboard, only: [:index]
      scope '/gitlab_credits_dashboard' do
        resources :users, only: [:show], controller: 'gitlab_credits_dashboard/users', param: :username,
          as: :gitlab_credits_dashboard_users, format: false,
          constraints: { username: Gitlab::PathRegex.root_namespace_route_regex }
        resources :credit_caps, only: [:index], controller: 'gitlab_credits_dashboard/credit_caps',
          as: :gitlab_credits_dashboard_credit_caps
      end

      get '/gitlab_duo_usage', to: redirect('groups/%{group_id}/-/settings/gitlab_duo/seat_utilization')

      scope module: 'remote_development' do
        get 'workspaces', action: :show, controller: 'workspaces'
      end

      resource :work_items, param: :work_item_type do
        get '(/*vueroute)', to: 'work_items#show', as: :work_items, format: false
      end
      resource :issues, only: [:show], controller: 'work_items'

      namespace :packages_and_registries do
        resources :virtual_registry_cleanup_policy, only: [:index]
      end
    end

    resources :group_members, only: [], concerns: :access_requestable do
      patch :override, on: :member
      put :unban, on: :member
      put :ban, on: :member

      collection do
        get :export_csv
      end
    end

    resource :two_factor_auth, only: [:destroy]

    get '/analytics', to: redirect('groups/%{group_id}/-/analytics/value_stream_analytics')
    resource :contribution_analytics, only: [:show]

    namespace :analytics do
      resource :ci_cd_analytics, only: :show, path: 'ci_cd'

      resources :dashboards, only: [:index], path: 'dashboards(/*vueroute)', format: false

      resource :devops_adoption, controller: :devops_adoption, only: :show
      resource :productivity_analytics, only: :show
      resources :coverage_reports, only: :index
      resource :merge_request_analytics, only: :show
      resource :repository_analytics, only: :show
      resource :cycle_analytics, only: :show, path: 'value_stream_analytics'
      scope module: :cycle_analytics, as: 'cycle_analytics', path: 'value_stream_analytics' do
        resources :value_streams do
          resources :stages, only: [:index] do
            member do
              get :average_duration_chart
              get :median
              get :average
              get :records
              get :count
            end
          end
        end
        resource :summary, controller: :summary, only: :show
        get '/time_summary' => 'summary#time_summary'
        get '/lead_times' => 'summary#lead_times'
        get '/cycle_times' => 'summary#cycle_times'
      end
      get '/cycle_analytics', to: redirect('-/analytics/value_stream_analytics')

      scope :type_of_work do
        resource :tasks_by_type, controller: :tasks_by_type, only: :show do
          get :top_labels
        end
      end
    end

    resource :ldap, only: [] do
      member do
        put :sync
      end
    end

    resource :issues_analytics, only: [:show]

    resource :insights, only: [:show], defaults: { trailing_slash: true } do
      collection do
        post :query
      end
    end

    resource :notification_setting, only: [:update]

    resources :ldap_group_links, only: [:index, :create, :destroy]
    resources :saml_group_links, only: [:index, :create, :destroy]
    resources :audit_events, only: [:index]
    resource :usage_quotas, only: [] do
      get '/', to: 'usage_quotas#root'
      get :pending_members
      get :subscription_history, defaults: { format: 'csv' }
    end

    resources :hooks, only: [:index, :create, :edit, :update, :destroy], constraints: { id: /\d+/ } do
      member do
        post :test
      end

      resources :hook_logs, only: [:show] do
        member do
          post :retry
        end
      end
    end

    resources :autocomplete_sources, only: [] do
      collection do
        get 'epics'
        get 'iterations'
        get 'vulnerabilities'
        get 'wikis'
      end
    end

    resources :billings, only: [:index] do
      collection do
        post :refresh_seats
      end
    end

    get :seat_usage, to: 'seat_usage#show'

    resource :minimal_access_provisioning_alert_dismissal, only: :create,
      controller: 'minimal_access_provisioning_alert_dismissals'

    resources :comment_templates, only: [:index, :show], action: :index

    resources :epics, concerns: :awardable, constraints: { id: /\d+/ }, except: [:create] do
      member do
        get '/descriptions/:version_id/diff', action: :description_diff, as: :description_diff
        delete '/descriptions/:version_id', action: :delete_description_version, as: :delete_description_version
        get :discussions, format: :json
        get :realtime_changes
        post :toggle_subscription
      end

      scope module: :epics do
        resources :notes, only: [:index, :create, :destroy, :update], concerns: :awardable, constraints: { id: /\d+/ }
      end

      collection do
        post :bulk_update
      end
    end

    resources :iterations, only: [:index, :new, :edit, :show], constraints: { id: /\d+/ }

    resources :iteration_cadences, path: 'cadences(/*vueroute)', action: :index do
      resources :iterations, only: [:index, :new, :edit, :show], constraints: { id: /\d+/ }, controller: :iteration_cadences, action: :index
    end

    resources :issues, only: [] do
      collection do
        post :bulk_update
      end
    end

    resources :merge_requests, only: [] do
      collection do
        post :bulk_update
      end
    end

    resources :todos, only: [:create]

    resources :epic_boards, only: [:index, :show]
    resources :protected_environments, only: [:create, :update, :destroy]

    namespace :security do
      resource :dashboard, only: [:show], controller: :dashboard
      resource :inventory, only: [:show], controller: :inventory
      resource :configuration, only: [:show], controller: :configuration
      resources :vulnerabilities, only: [:index]
      resources :agent_artifacts, only: [], constraints: { id: /\d+/ } do
        member do
          get :download
          get :download_session
        end
      end
      resources :compliance_frameworks do
        collection do
          post :import, to: 'compliance_dashboard/compliance_frameworks_import#create'
        end
      end
      namespace :compliance_dashboard do
        resources :frameworks, only: [:show], constraints: ->(req) {
          req.format == :json && req.path_parameters[:id].match?(/\d+/)
        }

        namespace :exports do
          get :compliance_status_report, constraints: { format: :csv }
          get :violations_report, constraints: { format: :csv }
        end
      end
      resource :compliance_dashboard, path: 'compliance_dashboard(/*vueroute)', only: [:show]
      resource :discover, only: [:show], controller: :discover
      resources :credentials, only: [:index, :destroy] do
        resources :resources, only: [] do
          put :revoke, controller: :credentials
        end
        member do
          put :revoke
        end
      end
      resources :policies, only: [:index, :new, :edit], constraints: { id: %r{[^/]+} } do
        collection do
          get :schema
        end
      end

      resources :policy_store, only: [:index, :new, :show, :edit], constraints: { id: /\d+/ }

      resource :dependency_firewall, only: [:show], controller: :dependency_firewall

      resources :merge_commit_reports, only: [:index], constraints: { format: :csv }
      resources :compliance_project_framework_reports, only: [:index], constraints: { format: :csv }
      resources :compliance_violation_reports, only: [:index], constraints: { format: :csv }
      resources :compliance_standards_adherence_reports, only: [:index], constraints: { format: :csv }
      resources :compliance_framework_reports, only: [:index], constraints: { format: :csv }
    end

    resources :dependencies, only: [:index] do
      collection do
        get :licenses, format: :json
        get :locations, format: :json
      end
    end

    resource :push_rules, only: [:update]

    resources :protected_branches, only: [:create, :update, :destroy]

    resource :saml_providers, path: 'saml', only: [:show, :create, :update] do
      callback_methods = Rails.env.test? ? [:get, :post] : [:post]
      match :callback, to: 'omniauth_callbacks#group_saml', via: callback_methods
      get :sso, to: 'sso#saml'
      post :sso, to: 'sso#saml'

      delete :unlink, to: 'sso#unlink'
      put :update_microsoft_application
    end

    resource :scim_oauth, only: [:create], controller: :scim_oauth

    resource :roadmap, only: [:show], controller: 'roadmap'

    resources :work_items, only: [], param: :iid do
      member do
        get '/descriptions/:version_id/diff', action: :description_diff, as: :description_diff
        delete '/descriptions/:version_id', action: :delete_description_version, as: :delete_description_version
      end
    end

    resource :discover, only: [:show]

    resources :runners, only: [] do
      collection do
        get :dashboard
      end
    end

    scope :automate do
      # Must stay above the catch-all, which would otherwise route governance to duo_agents_platform#show.
      get 'governance', to: 'automate/governance#index', as: :automate_governance, format: false
      get '/(*vueroute)' => 'duo_agents_platform#show', as: :automate, format: false
      get 'agent-sessions/:id', to: 'duo_agents_platform#show', as: :automate_agent_session, format: false
      get 'agents', to: 'duo_agents_platform#show', as: :automate_agents, format: false
      get 'agents/:id', to: 'duo_agents_platform#show', as: :automate_agent, format: false
      get 'flows', to: 'duo_agents_platform#show', as: :automate_flows, format: false
      get 'flows/:id', to: 'duo_agents_platform#show', as: :automate_flow, format: false
      get 'mcp-servers', to: 'duo_agents_platform#show', as: :automate_mcp_servers, format: false
    end

    draw :virtual_registries

    resources :secrets, path: 'secrets(/*vueroute)', only: [:index]
  end
end
