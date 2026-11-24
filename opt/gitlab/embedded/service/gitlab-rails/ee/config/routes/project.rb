# frozen_string_literal: true

constraints(::Projects::ProjectUrlConstraint.new) do
  scope(
    path: '*namespace_id',
    as: :namespace,
    namespace_id: Gitlab::PathRegex.full_namespace_route_regex
  ) do
    scope(
      path: ':project_id',
      constraints: { project_id: Gitlab::PathRegex.project_route_regex },
      module: :projects,
      as: :project
    ) do
      # Begin of the /-/ scope.
      # Use this scope for all new project routes.
      scope '-' do
        draw :google_cloud

        namespace :requirements_management do
          resources :requirements, only: [:index] do
            collection do
              post :import_csv
              post 'import_csv/authorize', to: 'requirements#authorize'
            end
          end
        end

        # Read doc/development/ai_features/duo_agent_platform.md before updating the automate routes
        scope :automate do
          # Must stay above the catch-all, which would otherwise route governance to duo_agents_platform#show.
          get 'governance', to: 'automate/governance#index', as: :automate_governance, format: false
          get '/(*vueroute)' => 'duo_agents_platform#show', as: :automate, format: false
          # Additional named routes for helpers
          # Used as hardcoded path in
          # https://gitlab.com/gitlab-org/gitlab/-/blob/e9b59c5de32c6ce4e14665681afbf95cf001c044/ee/app/assets/javascripts/ai/components/duo_workflow_action.vue#L76.
          get 'agent-sessions', to: 'duo_agents_platform#show', as: :automate_agent_sessions, format: false
          get 'agent-sessions/:id', to: 'duo_agents_platform#show', as: :automate_agent_session, format: false
          get 'agents', to: 'duo_agents_platform#show', as: :automate_agents, format: false
          get 'agents/:id', to: 'duo_agents_platform#show', as: :automate_agent, format: false
          get 'triggers', to: 'duo_agents_platform#show', as: :automate_flow_triggers, format: false
          get 'flows', to: 'duo_agents_platform#show', as: :automate_flows, format: false
          get 'flows/:id', to: 'duo_agents_platform#show', as: :automate_flow, format: false
          get 'skills', to: 'duo_agents_platform#show', as: :automate_skills, format: false
          get 'skills/:id', to: 'duo_agents_platform#show', as: :automate_skill, format: false
          get 'mcp-servers', to: 'duo_agents_platform#show', as: :automate_mcp_servers, format: false
          get 'software-factory', to: 'duo_agents_platform#show', as: :automate_software_factory, format: false
        end

        resources :duo_otel_workflows, only: [:create], controller: 'duo_otel_workflows'

        resource :github_updates, only: [], controller: 'import/sync/github_updates' do
          get :status
          post :update_now
          post :stop
        end

        namespace :quality do
          resources :test_cases, only: [:index, :new, :show]
        end

        resources :autocomplete_sources, only: [] do
          collection do
            get 'epics'
            get 'iterations'
            get 'vulnerabilities'
          end
        end

        resources :target_branch_rules, only: [:index, :create, :destroy]

        resources :comment_templates, only: [:index, :show], action: :index

        resources :automations, only: [:index]

        resources :subscriptions, only: [:create, :destroy]

        resources :protected_environments, only: [:create, :update, :destroy], constraints: { id: /\d+/ } do
          collection do
            get 'search'
          end
        end

        resources :audit_events, only: [:index]

        namespace :security do
          resources :dashboard, only: [:index], controller: :dashboard
          resources :vulnerability_report, only: [:index], controller: :vulnerability_report
          resource :compliance_dashboard, path: 'compliance_dashboard(/*vueroute)', only: [:show]
          resources :compliance_violations, only: [:show], constraints: { id: /\d+/ }
          resources :agent_artifacts, only: [], constraints: { id: /\d+/ } do
            member do
              get :download
              get :download_session
            end
          end
          resources :policies, only: [:index, :new, :edit], constraints: { id: %r{[^/]+} } do
            collection do
              get :schema
            end
          end

          # Read-only at the project level: policies are authored at the organization or
          # group, so there is deliberately no new/edit route here. The detail page
          # lands with the project query documents.
          resources :policy_store, only: [:index]

          resource :dependency_firewall, only: [:show], controller: :dependency_firewall

          resource :configuration, only: [], controller: :configuration do
            resource :corpus_management, only: [:show], controller: :corpus_management
            resource :api_fuzzing, only: :show, controller: :api_fuzzing_configuration
            resource :profile_library, only: [:show], controller: :dast_profiles do
              resources :dast_site_profiles, only: [:new, :edit]
              resources :dast_scanner_profiles, only: [:new, :edit]
            end
            resource :dast, only: :show, controller: :dast_configuration
            resource :secret_detection, only: :show, controller: :secret_detection_configuration
          end

          resource :discover, only: [:show], controller: :discover

          resources :scanned_resources, only: [:index]

          resources :vulnerabilities, only: [:show, :new] do
            member do
              get :discussions, format: :json
            end

            scope module: :vulnerabilities do
              resources :notes, only: [:index, :create, :destroy, :update], concerns: :awardable, constraints: { id: /\d+/ }
            end
          end
        end

        namespace :analytics do
          resources :code_reviews, only: [:index]
          resource :issues_analytics, only: [:show]
          get '/merge_request_analytics', to: redirect('%{namespace_id}/%{project_id}/-/analytics/dashboards/merge_request_analytics')
          resources :dashboards, only: [:index], path: 'dashboards(/*vueroute)', format: false

          scope module: :cycle_analytics, as: 'cycle_analytics', path: 'value_stream_analytics' do
            resources :value_streams
            get '/value_streams/:value_stream_id/stages/:id/average_duration_chart' => 'stages#average_duration_chart', as: 'average_duration_chart'
            get '/time_summary' => 'summary#time_summary'
          end
        end

        resources :push_rules, constraints: { id: /\d+/ }, only: [:update]
        resources :vulnerability_feedback, only: [:index, :create, :update, :destroy], constraints: { id: /\d+/ }
        namespace :vulnerability_feedback do
          get :count
        end
        resources :dependencies, only: [:index] do
          collection do
            get :licenses, format: :json
          end
        end

        resources :feature_flags, param: :iid do
          resources :feature_flag_issues, only: [:index, :create, :destroy], as: 'issues', path: 'issues'
        end

        resources :on_demand_scans, only: [:index, :new, :edit]

        namespace :integrations do
          namespace :jira do
            resources :issues, only: [:index, :show]
          end

          namespace :zentao do
            resources :issues, only: [:index, :show]
          end
        end

        resources :iterations, only: [:index, :show], constraints: { id: /\d+/ }

        resources :iteration_cadences, path: 'cadences(/*vueroute)', action: :index do
          resources :iterations, only: [:index, :show], constraints: { id: /\d+/ }, controller: :iteration_cadences, action: :index
        end

        namespace :incident_management, path: '' do
          resources :oncall_schedules, only: [:index], path: 'oncall_schedules'
          resources :escalation_policies, only: [:index], path: 'escalation_policies'
        end

        namespace :settings do
          resource :work_items, only: [:show], controller: 'work_items'
          namespace :gitlab_duo do
            get 'governance', as: nil, to: redirect { |params, request|
              path = "#{params[:namespace_id]}/#{params[:project_id]}/-/automate/governance"
              request.query_string.present? ? "#{path}?#{request.query_string}" : path
            }
            resource :agent_config, only: [:create], controller: 'agent_config'
          end
        end

        resources :secrets, path: 'secrets(/*vueroute)', only: [:index]

        resources :tracing, only: [:index, :show], controller: :tracing

        resources :metrics, only: [:index, :show], constraints: { id: %r{[^/]+}, type: /\w+/ }, controller: :metrics

        resources :logs, only: [:index], controller: :logs

        resources :merge_trains, only: [:index]

        put :transfer_personal
      end
      # End of the /-/ scope.

      # All new routes should go under /-/ scope.
      # Look for scope '-' at the top of the file.
      # rubocop: disable Cop/PutProjectRoutesUnderScope

      resources :path_locks, only: [:index, :destroy] do
        collection do
          post :toggle
        end
      end

      resource :insights, only: [:show], defaults: { trailing_slash: true } do
        collection do
          post :query
        end
      end
      # All new routes should go under /-/ scope.
      # Look for scope '-' at the top of the file.
      # rubocop: enable Cop/PutProjectRoutesUnderScope
    end
  end
end
