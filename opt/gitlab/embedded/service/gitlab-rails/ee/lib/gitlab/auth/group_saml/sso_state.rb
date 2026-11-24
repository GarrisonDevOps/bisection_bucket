# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class SsoState
        SESSION_STORE_KEY = :active_group_sso_sign_ins
        SESSION_EXPIRY_SUFFIX = '_session_not_on_or_after'

        def self.active_saml_sessions
          Gitlab::NamespacedSessionStore.new(SESSION_STORE_KEY).to_h
        end

        attr_reader :provider_id

        def initialize(saml_provider_id)
          @provider_id = saml_provider_id
        end

        def sessionless?
          !active_session_data.initiated?
        end

        def active?
          sessionless? || last_signin_at
        end

        def update_active(saml_provider, session_not_on_or_after: nil)
          active_session_data[provider_id] = saml_provider
          active_session_data["#{provider_id}#{SESSION_EXPIRY_SUFFIX}"] = session_not_on_or_after
        end

        def active_since?(cutoff)
          session_not_on_or_after = session_not_on_or_after_value.presence

          return active? unless cutoff || session_not_on_or_after
          return true if sessionless?
          return false unless last_signin_at

          return Time.current <= session_not_on_or_after if session_not_on_or_after

          last_signin_at >= cutoff
        end

        def session_not_on_or_after_value
          active_session_data["#{provider_id}#{SESSION_EXPIRY_SUFFIX}"]
        end

        private

        def last_signin_at
          active_session_data[provider_id]
        end

        def active_session_data
          Gitlab::NamespacedSessionStore.new(SESSION_STORE_KEY)
        end
      end
    end
  end
end
