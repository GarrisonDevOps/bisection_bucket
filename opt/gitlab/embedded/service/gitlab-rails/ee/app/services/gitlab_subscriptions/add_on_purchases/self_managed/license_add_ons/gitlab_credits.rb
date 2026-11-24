# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class GitlabCredits < Base
          private

          override :name
          def name
            :gitlab_credits
          end
        end
      end
    end
  end
end
