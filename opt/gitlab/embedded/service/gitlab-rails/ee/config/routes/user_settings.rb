# frozen_string_literal: true

namespace :user_settings do
  resources :active_sessions, only: [] do
    collection do
      get :saml, format: :json
    end
  end
end
