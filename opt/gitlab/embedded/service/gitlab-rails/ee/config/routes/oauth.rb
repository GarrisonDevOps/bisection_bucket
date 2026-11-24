# frozen_string_literal: true

namespace :oauth do
  scope path: 'geo', controller: :geo_auth, as: :geo do
    get 'auth'
    get 'callback'
    get 'logout'
  end

  scope path: 'mcp_connectors', controller: :mcp_connectors_auth, as: :mcp_connectors do
    get 'connect'
    get 'callback'
    post 'disconnect'
  end
end
