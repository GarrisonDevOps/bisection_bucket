# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module ProvisionServices
        class OrbitPromo < Base
          private

          override :license_type_supported?
          def license_type_supported?
            current_license.present?
          end

          def add_on_purchase
            GitlabSubscriptions::AddOnPurchase.for_self_managed.for_orbit_promo.first
          end
          strong_memoize_attr :add_on_purchase

          def license_add_on
            LicenseAddOns::OrbitPromo.new(license_restrictions)
          end
          strong_memoize_attr :license_add_on
        end
      end
    end
  end
end
