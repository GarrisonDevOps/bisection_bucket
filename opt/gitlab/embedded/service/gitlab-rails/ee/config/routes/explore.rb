# frozen_string_literal: true

namespace :explore do
  scope '/ai-catalog' do
    get '/agents', to: 'ai_catalog#index', as: :ai_catalog_agents, format: false
    get '/agents/:id', to: 'ai_catalog#index', as: :ai_catalog_agent, format: false
    get '/flows', to: 'ai_catalog#index', as: :ai_catalog_flows, format: false
    get '/flows/:id', to: 'ai_catalog#index', as: :ai_catalog_flow, format: false
    get '/skills', to: 'ai_catalog#index', as: :ai_catalog_skills, format: false
    get '/skills/:id', to: 'ai_catalog#index', as: :ai_catalog_skill, format: false
    get '/(*vueroute)' => 'ai_catalog#index', as: :ai_catalog, format: false
  end

  resources :analytics_dashboards, path: 'analytics_dashboards(/*vueroute)', only: [:index]
end
