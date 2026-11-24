# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class Info
          include ::Gitlab::Utils::StrongMemoize

          attr_reader :quantity, :started_on, :expires_on, :purchase_xid, :trial

          def initialize(quantity: nil, started_on: nil, expires_on: nil, purchase_xid: nil, trial: false)
            @quantity = quantity.to_i
            @started_on = convert_date(started_on)
            @expires_on = convert_date(expires_on)
            @purchase_xid = purchase_xid
            @trial = trial
          end

          def active?
            return false if started_on.blank? || expires_on.blank?

            today = Date.current

            started_on <= today && today < expires_on
          end

          private

          def convert_date(date)
            date&.to_date
          rescue Date::Error
            nil
          end
        end
      end
    end
  end
end
