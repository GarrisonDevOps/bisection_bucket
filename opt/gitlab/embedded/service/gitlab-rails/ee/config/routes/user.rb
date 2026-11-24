# frozen_string_literal: true

devise_scope :user do
  get '/users/auth/kerberos/negotiate' => 'omniauth_kerberos#negotiate'
  post '/users/password/complexity' => 'passwords#complexity'
end

scope '-/users', module: :users do
  resources :targeted_message_dismissals, only: [:create]
end

# Sign up
scope path: '/users/sign_up', module: :registrations, as: :users_sign_up do
  scope constraints: ::Onboarding::TrialUserConstraint.new do
    resource :welcome, only: [:show, :update], controller: 'trial_welcome'
  end

  scope constraints: ::Onboarding::InviteUserConstraint.new do
    resource :welcome, only: [:show, :update], controller: 'invite_welcome'
  end

  scope constraints: ::Onboarding::SubscriptionUserConstraint.new do
    resource :welcome, only: [:show, :update], controller: 'subscription_welcome'
  end

  scope constraints: ::Onboarding::FreeAutomaticTrialConstraint.new do
    resource :welcome, only: :update, controller: 'trial_welcome'
  end

  resource :welcome, only: [:show, :update], controller: 'welcome'
  resources :groups, only: [:new, :create]
  resource :customers_portal_redirect, only: [:show], controller: 'customers_portal_redirect'
end

scope(constraints: { username: Gitlab::PathRegex.root_namespace_route_regex }) do
  scope(path: 'users/:username', as: :user, controller: :users) do
    get :available_project_templates
    get :available_group_templates
  end
end
