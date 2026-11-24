# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    module EnabledNamespaces
      class CreateService
        include CommonMethods
        include Gitlab::ExclusiveLeaseHelpers

        MAX_ENABLED_NAMESPACES_PER_DISPLAY_NAMESPACE = 100
        CAP_LEASE_TTL = 10.seconds

        # lock: false is for callers that already hold the display namespace lease (BulkFindOrCreateService).
        def initialize(
          current_user:, enabled_namespace: Analytics::DevopsAdoption::EnabledNamespace.new, params: {}, lock: true)
          @enabled_namespace = enabled_namespace
          @params = params
          @current_user = current_user
          @lock = lock
        end

        def execute
          authorize!

          enabled_namespace.assign_attributes(namespace: namespace, display_namespace: display_namespace)

          return save_enabled_namespace unless cap_enabled?
          return create_within_cap unless lock

          # Serialises the count and the insert per display namespace so two requests cannot both pass at 99;
          # the count itself reads from the primary.
          in_lock(cap_lease_key, ttl: CAP_LEASE_TTL, retries: 3) { create_within_cap }
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          error_response(lock_failed_message, :lock_failed)
        end

        private

        attr_reader :enabled_namespace, :lock

        def response_payload
          { enabled_namespace: enabled_namespace }
        end

        def create_within_cap
          limit_reached? ? limit_reached_response : save_enabled_namespace
        end

        def save_enabled_namespace
          if enabled_namespace.save
            Analytics::DevopsAdoption::CreateSnapshotWorker.perform_async(enabled_namespace.id)

            ServiceResponse.success(payload: response_payload)
          else
            ServiceResponse.error(message: 'Validation error', payload: response_payload)
          end
        end

        def limit_reached?
          # Before its first write a request may read a lagging replica, which would undercount under the lease.
          ::Gitlab::Database::LoadBalancing::SessionMap
            .current(Analytics::DevopsAdoption::EnabledNamespace.load_balancer).use_primary do
            Analytics::DevopsAdoption::EnabledNamespace.for_display_namespaces(display_namespace).count >=
              MAX_ENABLED_NAMESPACES_PER_DISPLAY_NAMESPACE
          end
        end

        def limit_reached_response
          message = format(
            n_(
              'Display namespace has reached the limit of %{limit} enabled namespace',
              'Display namespace has reached the limit of %{limit} enabled namespaces',
              MAX_ENABLED_NAMESPACES_PER_DISPLAY_NAMESPACE
            ),
            limit: MAX_ENABLED_NAMESPACES_PER_DISPLAY_NAMESPACE
          )

          error_response(message, :limit_reached)
        end

        def error_response(message, reason)
          # The mutations read errors from the record, not from the response.
          enabled_namespace.errors.add(:base, message)

          ServiceResponse.error(message: message, reason: reason, payload: response_payload)
        end
      end
    end
  end
end
