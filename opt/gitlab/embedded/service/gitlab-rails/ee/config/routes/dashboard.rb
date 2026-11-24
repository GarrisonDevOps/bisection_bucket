# frozen_string_literal: true

resource :dashboard, controller: 'dashboard', only: [] do
  scope module: :dashboard do
    resources :projects, only: [] do
      collection do
        get :removed, to: redirect('dashboard/projects/inactive')
      end
    end

    resource :orbit, only: [:show], controller: 'orbit' do
      get '(*vueroute)', action: :show, as: :vueroute
    end
  end
end
