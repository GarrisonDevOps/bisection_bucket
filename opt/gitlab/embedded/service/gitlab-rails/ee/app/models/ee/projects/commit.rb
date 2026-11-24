# frozen_string_literal: true

module EE
  module Projects
    module Commit
      extend ::Gitlab::Utils::Override
      include ::Ai::Model

      DUO_SESSION_TRAILER_KEY = 'Duo-Session'
      DUO_SESSION_TRAILER_REGEX = /^#{Regexp.escape(DUO_SESSION_TRAILER_KEY)}: /m

      override :has_agent_session?
      def has_agent_session?
        return false unless project&.project_setting&.dap_session_tracking_enabled?

        return trailers.key?(DUO_SESSION_TRAILER_KEY) if trailers.present?
        return false if safe_message.blank?

        safe_message.match?(DUO_SESSION_TRAILER_REGEX)
      end

      def resource_parent
        project
      end
    end
  end
end
