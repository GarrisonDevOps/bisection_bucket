# frozen_string_literal: true

module EE
  module Import
    module SourceUser
      extend ::Gitlab::Utils::Override

      override :bypass_placeholder_confirmation_allowed?
      def bypass_placeholder_confirmation_allowed?
        return true if super

        enterprise_bypass_placeholder_confirmation_allowed? || service_account_reassignment?
      end

      def enterprise_bypass_placeholder_confirmation_allowed?
        ::Import::UserMapping::EnterpriseBypassAuthorizer.new(namespace, reassign_to_user, reassigned_by_user).allowed?
      end

      def service_account_reassignment?
        ::Import::UserMapping::ServiceAccountBypassAuthorizer.new(namespace, reassign_to_user,
          reassigned_by_user).allowed?
      end
    end
  end
end
