# frozen_string_literal: true

module API
  module Entities
    module SecretsManagement
      # Shaped to match external-secrets.io/v1.VaultProvider so clients can map
      # the response onto a Vault provider config, with the token inlined.
      # `secrets_path` is the base path under the KV engine where secrets live;
      # clients prepend it to a secret name (for example, the ESO `remoteRef.key`).
      class AccessToken < Grape::Entity
        expose :expires_at, documentation: { type: 'String', example: '2026-05-27T10:35:00Z' }

        # rubocop:disable Style/SymbolProc -- Grape calls exposure blocks with (object, options); a symbol proc would pass options as an argument
        expose :provider, documentation: { type: 'Hash' } do
          expose :vault, documentation: { type: 'Hash' } do
            expose :server, documentation: { type: 'String', example: 'https://openbao.example.com' } do |token|
              token.server_url
            end
            expose :namespace, documentation: { type: 'String', example: 'org_5/group_42/project_99' }
            expose :path, documentation: { type: 'String', example: 'secrets/kv' } do |token|
              token.kv_mount
            end
            expose :version, documentation: { type: 'String', example: 'v2' } do |_token|
              'v2'
            end
            expose :secrets_path, documentation: { type: 'String', example: 'explicit' } do |token|
              token.secrets_path
            end

            expose :auth, documentation: { type: 'Hash' } do
              expose :jwt, documentation: { type: 'Hash' } do
                expose :path, documentation: { type: 'String', example: 'api_jwt/cel' } do |token|
                  token.auth_mount
                end
                expose :role, documentation: { type: 'String', example: 'all_api' } do |token|
                  token.auth_role
                end
                expose :token, documentation: { type: 'String' }
              end
            end
          end
        end
        # rubocop:enable Style/SymbolProc
      end
    end
  end
end
