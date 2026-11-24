# frozen_string_literal: true

module EE
  module Import
    module MemberLimitCheckService
      extend ::Gitlab::Utils::Override

      private

      override :validate_membership_status
      def validate_membership_status
        return ServiceResponse.error(message: 'membership is locked') if importable.membership_locked?

        super
      end
    end
  end
end
