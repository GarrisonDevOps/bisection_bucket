# frozen_string_literal: true

module Users
  module IdentityVerification
    class AuthorizeDuo
      attr_reader :user, :ai_feature, :root_namespace

      def initialize(user:, ai_feature:, root_namespace:, entitlement: nil)
        @user = user
        @ai_feature = ai_feature
        @root_namespace = root_namespace
        @entitlement = entitlement
      end

      def identity_verification_required?
        return false unless duo_agent_platform_feature?
        return false unless verification_enforced?
        return false unless entitlement.allowed?
        return false unless entitlement.unpaid?

        !user.identity_verified?
      end

      private

      def entitlement
        @entitlement ||= user.duo_entitlement(ai_feature, root_namespace: root_namespace)
      end

      def duo_agent_platform_feature?
        ::Ai::UserAuthorizable::THROUGH_NAMESPACE_ACCESS_FEATURE_MAP[ai_feature] ==
          ::Ai::UserAuthorizable::DAP_ACCESS_GROUP
      end

      def verification_enforced?
        ::Feature.enabled?(:dap_require_identity_verification, root_namespace)
      end
    end
  end
end
