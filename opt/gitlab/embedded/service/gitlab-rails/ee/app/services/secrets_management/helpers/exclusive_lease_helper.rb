# frozen_string_literal: true

module SecretsManagement
  module Helpers
    module ExclusiveLeaseHelper
      include Gitlab::ExclusiveLeaseHelpers

      DEFAULT_LEASE_TIMEOUT = 30.seconds.to_i

      def with_exclusive_lease_for(object, lease_timeout: DEFAULT_LEASE_TIMEOUT)
        in_lock(lease_key(object), ttl: lease_timeout, retries: 0) { yield }
      rescue FailedToObtainLockError
        obtain_lease_failure_response
      end

      def obtain_lease_failure_response
        message = 'Another secret operation in progress'
        ServiceResponse.error(message: message)
      end

      def lease_key(object)
        if object.is_a?(Project)
          "project_secret_operation:project_#{project.id}"
        elsif object.is_a?(Group)
          "group_secret_operation:group_#{group.id}"
        end
      end
    end
  end
end
