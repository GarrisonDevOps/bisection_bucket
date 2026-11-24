# frozen_string_literal: true

module Notifications
  module MobileDevicePushSubscriptions
    # Removes every subscription for a device token across all APNs
    # environments, whichever user registered it. Possession of the token is
    # the authority, as it is for RegisterService's reassignment: APNs tokens
    # identify the device, not the account. This lets the account now signed
    # in on a device clear a previous account's registration whose own
    # sign-out delete never reached the server.
    class UnregisterService
      include Gitlab::Loggable

      def initialize(user:, device_token:)
        @user = user
        @device_token = device_token
      end

      def execute
        other_user_ids = MobileDevicePushSubscription.other_user_ids_for_device_token(device_token, user)
        deleted = MobileDevicePushSubscription.with_device_token(device_token).delete_all

        return ServiceResponse.error(message: 'Push subscription not found', reason: :not_found) if deleted == 0

        log_other_users_deletion(other_user_ids) if other_user_ids.any?

        ServiceResponse.success
      end

      private

      attr_reader :user, :device_token

      # Names the users whose rows went away, so an abuse investigation can
      # follow a token from the account that deleted it to the ones it left.
      def log_other_users_deletion(other_user_ids)
        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'Removed mobile push subscriptions registered by other users for a device token',
            Labkit::Fields::GL_USER_ID => user.id,
            other_user_ids: other_user_ids.uniq,
            other_users_subscriptions_count: other_user_ids.size
          )
        )
      end
    end
  end
end
