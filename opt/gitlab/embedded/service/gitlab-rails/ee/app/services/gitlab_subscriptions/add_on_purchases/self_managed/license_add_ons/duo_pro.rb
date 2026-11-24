# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class DuoPro < Base
          private

          override :name
          def name
            :code_suggestions
          end

          override :name_in_license
          def name_in_license
            :duo_pro
          end
        end
      end
    end
  end
end
