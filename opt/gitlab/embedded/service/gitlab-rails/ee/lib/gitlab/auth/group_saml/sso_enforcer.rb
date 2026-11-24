# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class SsoEnforcer
        DEFAULT_SESSION_TIMEOUT = 1.day
        BYPASS_ENFORCEMENT_KEY = :group_saml_sso_enforcement_bypassed

        class << self
          # Disables group SAML SSO enforcement checks for the given block.
          def bypassing_enforcement
            previous = Thread.current[BYPASS_ENFORCEMENT_KEY]
            Thread.current[BYPASS_ENFORCEMENT_KEY] = true
            yield
          ensure
            Thread.current[BYPASS_ENFORCEMENT_KEY] = previous
          end

          def enforcement_bypassed?
            Thread.current[BYPASS_ENFORCEMENT_KEY] == true
          end

          def sessions_time_remaining_for_expiry
            active_sessions = SsoState.active_saml_sessions

            active_sessions.filter_map do |key, last_sign_in_at|
              # Skip session expiry keys - we only want provider sessions
              next if key.to_s.end_with?(SsoState::SESSION_EXPIRY_SUFFIX)
              next unless last_sign_in_at

              # Check for SAML-specific session expiry
              saml_expiry_key = "#{key}#{SsoState::SESSION_EXPIRY_SUFFIX}"
              saml_expires_at = active_sessions[saml_expiry_key]

              determine_time_remaining_with_session_not_on_or_after(
                key, last_sign_in_at, saml_expires_at
              )
            end
          end

          def access_restricted?(user:, resource:, session_timeout: DEFAULT_SESSION_TIMEOUT, skip_owner_check: false)
            return false if enforcement_bypassed?
            return false if user&.can_read_all_resources?

            group = resource.is_a?(::Group) ? resource : resource.group

            return false unless group

            saml_provider = group.root_saml_provider

            return false unless saml_provider

            return false if user_authorized?(user, resource, skip_owner_check)

            new(saml_provider, user: user, session_timeout: session_timeout).access_restricted?
          end

          # Given an array of groups or subgroups, return an array
          # of root groups that are access restricted for the user
          def access_restricted_groups(groups, user: nil)
            return [] unless groups.any?

            ::Namespaces::Preloaders::GroupRootAncestorPreloader.new(groups, [:saml_provider]).execute
            root_ancestors = groups.map(&:root_ancestor).uniq

            root_ancestors.select do |root_ancestor|
              new(root_ancestor.saml_provider, user: user).access_restricted?
            end
          end

          private

          def user_authorized?(user, resource, skip_owner_check)
            return true if resource.public? && !resource_member?(resource, user)
            return true if resource.is_a?(::Group) && resource.root? && resource.owned_by?(user) && !skip_owner_check

            false
          end

          def resource_member?(resource, user)
            user && user.is_a?(::User) && resource.member?(user)
          end

          def determine_time_remaining_with_session_not_on_or_after(key, last_sign_in_at, saml_expires_at)
            # If SessionNotOnOrAfter attribute is present use the same value to determine session expiry
            expires_at = saml_expires_at.presence || (last_sign_in_at + DEFAULT_SESSION_TIMEOUT)

            # expires_at is DateTime; convert to Time; Time - Time yields a Float
            time_remaining_for_expiry = expires_at.to_time - Time.current

            { provider_id: key, time_remaining: time_remaining_for_expiry }
          end
        end

        attr_reader :saml_provider, :user, :session_timeout

        def initialize(saml_provider, user: nil, session_timeout: DEFAULT_SESSION_TIMEOUT)
          @saml_provider = saml_provider
          @user = user
          @session_timeout = session_timeout
        end

        def update_session(session_not_on_or_after: nil)
          SsoState.new(saml_provider.id).update_active(DateTime.now, session_not_on_or_after: session_not_on_or_after)
        end

        def active_session?
          SsoState.new(saml_provider.id).active_since?(session_timeout.ago)
        end

        def access_restricted?
          return false if self.class.enforcement_bypassed?
          return false if user_authorized?

          saml_enforced? && !active_session?
        end

        private

        def saml_enforced?
          return true if saml_provider&.enforced_sso?
          return false unless user && group
          return false unless saml_provider&.enabled? && group.licensed_feature_available?(:group_saml)

          user.group_sso?(group)
        end

        def user_authorized?
          return false unless user

          return true unless in_context_of_user_web_activity?

          return true if user.can_read_all_resources?

          false
        end

        def in_context_of_user_web_activity?
          Gitlab::Session.current &&
            Gitlab::Session.current.dig('warden.user.user.key', 0, 0) == user.id
        end

        def group
          saml_provider&.group
        end
      end
    end
  end
end
