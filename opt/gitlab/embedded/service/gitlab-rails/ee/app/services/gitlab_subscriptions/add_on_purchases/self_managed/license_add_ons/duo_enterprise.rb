# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class DuoEnterprise < Base
          private

          override :name
          def name
            :duo_enterprise
          end
        end
      end
    end
  end
end
