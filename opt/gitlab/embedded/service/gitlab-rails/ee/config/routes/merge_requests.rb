# frozen_string_literal: true

resources :merge_requests, only: [], constraints: { id: /\d+/ } do
  member do
    get '/descriptions/:version_id/diff', action: :description_diff, as: :description_diff
    delete '/descriptions/:version_id', action: :delete_description_version, as: :delete_description_version
    get :metrics_reports
    get :license_scanning_reports
    get :license_scanning_reports_collapsed

    # We intentionally need get here since this is invoked via a callback from the SAML Identity Provider(OmniAuth)
    get :saml_approval, action: :create, controller: 'merge_requests/saml_approvals'
  end
end
