# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    module EnabledNamespaces
      class BulkFindOrCreateService
        include CommonMethods
        include Gitlab::ExclusiveLeaseHelpers

        # Unrenewed on purpose: the lease only has to cover the count-then-insert of at most 100 creates,
        # and past the cap the loop only reads.
        CAP_LEASE_TTL = 1.minute

        def initialize(current_user:, params: {})
          @params = params
          @current_user = current_user
        end

        def execute
          authorize!

          return find_or_create_all unless cap_enabled?

          # One lease for the whole request; the per-row lease in CreateService is skipped with lock: false.
          in_lock(cap_lease_key, ttl: CAP_LEASE_TTL, retries: 3) { find_or_create_all }
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          ServiceResponse.error(message: lock_failed_message, reason: :lock_failed, payload: { enabled_namespaces: [] })
        end

        def authorize!
          services.each(&:authorize!)
        end

        private

        def find_or_create_all
          limit_response = nil

          enabled_namespaces = services.filter_map do |service|
            if limit_response
              # Past the cap every create would fail the same way, so only look up rows that already exist.
              service.find_enabled_namespace
            else
              response = service.execute
              limit_response = response if response.reason == :limit_reached
              response.payload[:enabled_namespace]
            end
          end

          payload = { enabled_namespaces: enabled_namespaces }

          if limit_response
            ServiceResponse.error(message: limit_response.message, reason: :limit_reached, payload: payload)
          else
            ServiceResponse.success(payload: payload)
          end
        end

        def services
          @services ||= params[:namespaces].uniq.map do |namespace|
            FindOrCreateService.new(current_user: current_user,
              params: { namespace: namespace, display_namespace: params[:display_namespace] }, lock: false)
          end
        end
      end
    end
  end
end
