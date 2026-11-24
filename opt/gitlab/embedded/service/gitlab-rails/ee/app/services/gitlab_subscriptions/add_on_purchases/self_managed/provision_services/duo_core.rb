# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module ProvisionServices
        class DuoCore < Base
          private

          def add_on_purchase
            GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_core.first
          end
          strong_memoize_attr :add_on_purchase

          def license_add_on
            LicenseAddOns::DuoCore.new(license_restrictions)
          end
          strong_memoize_attr :license_add_on
        end
      end
    end
  end
end
