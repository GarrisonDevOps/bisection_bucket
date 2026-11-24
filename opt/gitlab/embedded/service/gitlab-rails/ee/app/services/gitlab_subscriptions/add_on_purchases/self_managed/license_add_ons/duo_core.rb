# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class DuoCore < Base
          private

          override :name
          def name
            :duo_core
          end
        end
      end
    end
  end
end
