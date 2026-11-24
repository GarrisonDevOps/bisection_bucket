# frozen_string_literal: true

namespace :google_cloud do
  resources :artifact_registry, only: :index

  get '/artifact_registry/projects/:project/locations/:location/repositories/:repository/dockerImages/:image',
    to: 'artifact_registry#show',
    as: :artifact_registry_image
end
