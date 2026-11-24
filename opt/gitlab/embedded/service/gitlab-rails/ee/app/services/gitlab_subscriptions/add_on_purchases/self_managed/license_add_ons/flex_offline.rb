# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class FlexOffline < Base
          private

          override :name
          def name
            :flex_offline
          end
        end
      end
    end
  end
end
