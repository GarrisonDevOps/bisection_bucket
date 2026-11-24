# frozen_string_literal: true

module Groups
  module EnterpriseUsers
    class BaseService
      def execute
        raise NotImplementedError
      end

      private

      attr_reader :user, :group

      def error(message, reason: nil)
        ServiceResponse.error(message: message, payload: response_payload, reason: reason)
      end

      def success
        ServiceResponse.success(payload: response_payload)
      end

      def response_payload
        { group: group, user: user }
      end

      def log_info(message:)
        Gitlab::AppLogger.info(
          class: self.class.name,
          group_id: group.id,
          user_id: user.id,
          message: message
        )
      end
    end
  end
end
