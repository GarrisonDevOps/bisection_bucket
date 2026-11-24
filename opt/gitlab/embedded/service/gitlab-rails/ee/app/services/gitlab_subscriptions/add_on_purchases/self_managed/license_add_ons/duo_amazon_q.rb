# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class DuoAmazonQ < Base
          private

          override :name
          def name
            :duo_amazon_q
          end
        end
      end
    end
  end
end
