# frozen_string_literal: true

module Gitlab
  module Llm
    class Tracking
      # Names whose `client` value differs from their client type: the values
      # that predate ClientIdentity, so existing dashboards keep working, plus
      # `duo_cli`, which keeps the Duo CLI apart from the generic `cli` type.
      LEGACY_CLIENTS = {
        'vscode' => 'vscode',
        'jetbrains' => 'jetbrains',
        'jetbrains-bundled' => 'jetbrains_bundled',
        'visual-studio' => 'visual_studio',
        'neovim' => 'neovim',
        'glab' => 'gitlab_cli',
        'duo-cli' => 'duo_cli'
      }.freeze

      WEB_CLIENT = 'web'
      WEB_IDE_CLIENT = 'web_ide'

      PLATFORM_VS_CODE = 'vs_code_extension'

      def self.event_for_ai_message(category, action, ai_message:)
        ::Gitlab::Tracking.event(
          category,
          action,
          label: ai_message.ai_action.to_s,
          property: ai_message.request_id,
          user: ai_message.user,
          client: client(user_agent: ai_message.context.user_agent, platform_origin: ai_message.platform_origin)
        )
      end

      # Prefers the identity of the request lineage (also set inside Sidekiq
      # jobs); the User-Agent is only for callers with no such context.
      def self.client(user_agent: nil, platform_origin: nil)
        identity = ::Gitlab::Tracking::ClientIdentity.current ||
          ::Gitlab::Tracking::ClientIdentity.from_user_agent(user_agent)
        client = legacy_client(identity)
        return client unless client == WEB_CLIENT

        # Web IDE has the same `user agent` as web, and same `platform_origin` as the VS Code IDE.
        # So we need to look at both factors to distinguish it.
        platform_origin == PLATFORM_VS_CODE ? WEB_IDE_CLIENT : WEB_CLIENT
      end

      def self.legacy_client(identity)
        return WEB_CLIENT if identity.type == 'browser'

        LEGACY_CLIENTS[identity.name] || identity.type
      end

      private_class_method :legacy_client
    end
  end
end
