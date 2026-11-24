# frozen_string_literal: true

resources :virtual_registries, only: [:index]
namespace :virtual_registries do
  namespace :maven do
    resources :registries_and_upstreams, path: '', only: [:index]
    resources :registries, only: [:new, :create, :show, :edit, :update, :destroy]
    resources :upstreams, only: [:show, :edit]
  end

  namespace :container do
    get '/(*vueroute)', action: :index, format: false
    # Additional routes for helpers, used as path in feature specs
    resources :registries, only: [:index, :new, :show, :edit], controller: :container, action: :index
    resources :upstreams, only: [:index, :show, :edit], controller: :container, action: :index
  end
end
