# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module ProvisionServices
        class AddOns
          PROVISION_SERVICES = [
            DuoExclusive,
            SelfHostedDap,
            DuoCore,
            GitlabCredits,
            SecretsManager,
            FlexOffline,
            OrbitPromo
          ].freeze

          def execute
            error_messages = []
            add_on_purchases = []

            PROVISION_SERVICES.each do |service|
              result = service.new.execute

              if result.error?
                error_messages << result.message
              else
                add_on_purchase = result.payload&.dig(:add_on_purchase)
                add_on_purchases << add_on_purchase if add_on_purchase
              end
            end

            if error_messages.empty?
              ServiceResponse.success(
                message: 'Successfully processed add-ons',
                payload: { add_on_purchases: add_on_purchases }
              )
            else
              ServiceResponse.error(
                message: "Error processing one or more add-ons: #{error_messages.join(', ')}",
                payload: { add_on_purchases: add_on_purchases }
              )
            end
          end
        end
      end
    end
  end
end
