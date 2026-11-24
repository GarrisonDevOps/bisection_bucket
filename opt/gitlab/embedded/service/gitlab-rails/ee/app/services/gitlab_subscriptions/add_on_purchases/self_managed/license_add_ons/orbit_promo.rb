# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class OrbitPromo < Base
          private

          override :name
          def name
            :orbit_promo
          end
        end
      end
    end
  end
end
