# frozen_string_literal: true

module Gitlab
  module Auth
    # Shared gating for every entry point that verifies or issues a
    # StatelessAccessToken, so they can't drift apart.
    #
    # Lives here (not under EE::Gitlab::Auth) since it has no CE counterpart
    # to extend; the EE:: namespace is reserved for extensions of an
    # existing CE class.
    module StatelessAccessTokenGate
      POLICY_STORE_SCOPE = 'read_security_policies'
      DUO_WORKFLOW_SCOPES = (::Gitlab::Auth::AI_WORKFLOW_SCOPES + [::Gitlab::Auth::MCP_SCOPE]).map(&:to_s).freeze

      def self.enabled?(token)
        gating_user = token.identities.present? ? token.identity_user : token.user
        scopes = token.raw_scopes

        policy_store_scoped = scopes.include?(POLICY_STORE_SCOPE)
        duo_scoped = (scopes & DUO_WORKFLOW_SCOPES).any?

        # No caller mixes these today; reject rather than pick one flag and
        # silently ignore the other.
        return false unless [policy_store_scoped, duo_scoped].one?

        flag_enabled?(policy_store: policy_store_scoped, user: gating_user)
      end

      def self.issuance_enabled?(user)
        flag_enabled?(policy_store: false, user: user) && ::CloudConnector::Keys.valid.present?
      end

      def self.flag_enabled?(policy_store:, user:)
        if policy_store
          ::Feature.enabled?(:security_policy_store_stateless_access_token_auth, user)
        else
          ::Feature.enabled?(:duo_workflow_use_token_issuer, user)
        end
      end
      private_class_method :flag_enabled?
    end
  end
end
