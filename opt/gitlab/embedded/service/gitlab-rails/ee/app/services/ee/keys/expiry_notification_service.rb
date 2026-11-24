# frozen_string_literal: true

module EE
  module Keys # rubocop:disable Gitlab/BoundedContexts -- prepended class is not inside a bounded context namespace
    module ExpiryNotificationService
      extend ::Gitlab::Utils::Override

      override :allowed?
      def allowed?
        return false if user.ssh_keys_disabled?

        super
      end
    end
  end
end
