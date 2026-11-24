# frozen_string_literal: true

module EE
  module UserSettings
    module ActiveSessionsController
      # dotcom-focused endpoint to return time remaining on existing SAML sessions
      # since we want only session data for current device / browser, this endpoint must be
      # in a regular app controller, not in the Grape API. client-side JS does not have access to
      # _gitlab_session_abc123 cookie
      def saml
        session_info = ::Gitlab::Auth::GroupSaml::SsoEnforcer.sessions_time_remaining_for_expiry

        session_info = session_info.map do |item|
          time_remaining = item[:time_remaining].in_milliseconds.to_i
          time_remaining = 0 if time_remaining <= 0

          {
            provider_id: item[:provider_id],
            time_remaining_ms: time_remaining
          }
        end
        render json: session_info
      end
    end
  end
end
