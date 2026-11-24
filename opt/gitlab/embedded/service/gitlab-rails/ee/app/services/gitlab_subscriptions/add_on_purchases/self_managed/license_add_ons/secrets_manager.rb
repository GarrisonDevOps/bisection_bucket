# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class SecretsManager < Base
          private

          override :name
          def name
            :secrets_manager
          end
        end
      end
    end
  end
end
