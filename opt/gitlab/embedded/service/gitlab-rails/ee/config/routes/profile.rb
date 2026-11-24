# frozen_string_literal: true

resource :profile, only: [] do
  scope module: :profiles do
    resources :usage_quotas, only: [:index]
    resources :gitlab_credits_dashboard, only: [:index]
    resources :billings, only: [:index]
    resources :designated_beneficiaries, only: [:create, :update, :destroy], path: 'designated-beneficiaries'
  end
end
