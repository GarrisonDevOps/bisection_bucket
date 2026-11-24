# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class SelfHostedDap < Base
          private

          override :name
          def name
            :self_hosted_dap
          end
        end
      end
    end
  end
end
