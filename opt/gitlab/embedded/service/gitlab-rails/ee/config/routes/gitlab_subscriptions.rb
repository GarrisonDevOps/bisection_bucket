# frozen_string_literal: true

scope module: :gitlab_subscriptions do
  constraints(GitlabSubscriptions::TrialTypeConstraint.new) do
    # saas => GitlabSubscriptions::TrialsController
    resources :trials, only: [:new, :create]
  end
  # self managed, excluding Dedicated which is already Ultimate => GitlabSubscriptions::SelfManaged::TrialsController,
  # which redirects to the customers portal when CustomersDot self-service trials are unavailable.
  constraints(GitlabSubscriptions::SelfManaged::TrialExperienceConstraint.new) do
    resource :trials, only: [:new, :create], controller: 'self_managed/trials', as: :self_managed_trials
  end

  resources :groups, only: [:new, :create], path: 'subscriptions/groups', as: :gitlab_subscriptions_groups
  resource :subscriptions, only: [:new] do
    get :buy_minutes
    get :buy_storage
    get :upgrade_base_plan
    get :payment_form
    post :validate_payment_method
  end
  resources :hand_raise_leads, only: :create, path: 'gitlab_subscriptions/hand_raise_leads',
    as: 'gitlab_subscriptions_hand_raise_leads' do
    collection do
      post :track_cart_abandonment
    end
  end
end
