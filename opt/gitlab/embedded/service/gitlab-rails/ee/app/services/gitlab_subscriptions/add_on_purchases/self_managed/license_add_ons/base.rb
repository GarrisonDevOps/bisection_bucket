# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module SelfManaged
      module LicenseAddOns
        class Base
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          MethodNotImplementedError = Class.new(StandardError)

          attr_reader :restrictions

          def initialize(restrictions)
            @restrictions = restrictions
          end

          def quantity
            add_ons_info.sum(&:quantity)
          end
          strong_memoize_attr :quantity

          def active?
            quantity > 0
          end

          # rubocop: disable CodeReuse/ActiveRecord -- SystemDefined::AddOn is a fixed items model, not a real AR model
          def add_on
            GitlabSubscriptions::SystemDefined::AddOn.find_by!(name: name.to_s)
          end
          # rubocop: enable CodeReuse/ActiveRecord
          strong_memoize_attr :add_on

          def starts_at
            add_ons_info.filter_map(&:started_on).min
          end
          strong_memoize_attr :starts_at

          def expires_on
            add_ons_info.filter_map(&:expires_on).max
          end
          strong_memoize_attr :expires_on

          def purchase_xid
            add_ons_info.filter_map(&:purchase_xid).first
          end
          strong_memoize_attr :purchase_xid

          def trial?
            add_ons_info.map(&:trial).uniq == [true]
          end
          strong_memoize_attr :trial?

          private

          def name
            raise MethodNotImplementedError
          end

          # needed to handle code_suggestions => duo_pro naming difference
          def name_in_license
            name
          end

          def add_ons_info
            return [] unless add_ons_in_license

            add_ons_in_license.map do |info_hash|
              attributes = info_hash.slice(:quantity, :started_on, :expires_on, :purchase_xid, :trial)

              Info.new(**attributes)
            end.filter(&:active?)
          end
          strong_memoize_attr :add_ons_info

          def add_ons_in_license
            return [] unless restrictions

            restrictions.deep_symbolize_keys.dig(:add_on_products, name_in_license)
          end
          strong_memoize_attr :add_ons_in_license
        end
      end
    end
  end
end
