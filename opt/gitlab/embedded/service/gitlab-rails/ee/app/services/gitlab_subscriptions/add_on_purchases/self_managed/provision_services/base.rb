# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module ProvisionServices
        class Base
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          AddOnPurchaseSyncError = Class.new(StandardError)
          MethodNotImplementedError = Class.new(StandardError)

          delegate :add_on, :quantity, :starts_at, :expires_on, :purchase_xid, to: :license_add_on, allow_nil: true

          def execute
            result = license_has_add_on? ? create_or_update_add_on_purchase : expire_prior_add_on_purchase
            return result if result.success?

            error = AddOnPurchaseSyncError.new(
              "Error syncing subscription add-on purchases. Message: #{result[:message]}"
            )

            Gitlab::ErrorTracking.track_and_raise_for_dev_exception(error)
            ServiceResponse.error(message: error.message)
          end

          private

          def license_has_add_on?
            license_type_supported? && quantity.to_i > 0
          end

          def license_type_supported?
            !!current_license&.cloud_license?
          end

          def add_on_purchase
            raise MethodNotImplementedError
          end

          def current_license
            License.current
          end
          strong_memoize_attr :current_license

          def license_restrictions
            current_license&.license&.restrictions
          end

          def empty_success_response
            ServiceResponse.success(payload: { add_on_purchase: nil })
          end

          def create_or_update_add_on_purchase
            service_class = if add_on_purchase
                              GitlabSubscriptions::AddOnPurchases::UpdateService
                            else
                              GitlabSubscriptions::AddOnPurchases::CreateService
                            end

            service_class.new(namespace, add_on, attributes).execute
          end

          def namespace
            nil # self-managed is unrelated to namespaces
          end

          def attributes
            {
              add_on_purchase: add_on_purchase,
              started_on: starts_at,
              expires_on: expires_on,
              purchase_xid: purchase_xid,
              quantity: quantity,
              trial: trial?
            }
          end

          def expire_prior_add_on_purchase
            return empty_success_response unless add_on_purchase

            GitlabSubscriptions::AddOnPurchases::SelfManaged::ExpireService.new(add_on_purchase).execute
          end

          def trial?
            !!license_add_on&.trial?
          end
        end
      end
    end
  end
end
