# frozen_string_literal: true

module EE
  module Members
    module MembershipLockValidation
      extend ::Gitlab::Utils::Override

      private

      def membership_locked?(source, service_account: false)
        source.membership_locked_for?(current_user, service_account: service_account)
      end
    end
  end
end
