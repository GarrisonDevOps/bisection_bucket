# frozen_string_literal: true

# SecretsManagerClient lives in ee/lib, which Zeitwerk reloads in development. A reload
# discards the class and its memoized configuration, so configure inside to_prepare,
# which runs again after every reload rather than once at boot.
Rails.application.config.to_prepare do
  SecretsManagement::SecretsManagerClient.configure do |c|
    c.host = if Rails.env.test?
               "http://127.0.0.1:9800"
             else
               SecretsManagement::ProjectSecretsManager.internal_server_url
             end

    c.base_path = 'v1'
  end
end
