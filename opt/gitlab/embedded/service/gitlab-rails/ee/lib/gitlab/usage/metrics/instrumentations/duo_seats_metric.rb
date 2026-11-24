# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoSeatsMetric < GenericMetric
          SUBSCRIPTION_TYPES = %w[pro enterprise amazon_q].freeze
          SEATS_TYPES = %w[purchased assigned].freeze

          def initialize(metric_definition)
            super

            return if options[:subscription_type].in?(SUBSCRIPTION_TYPES) && options[:seats_type].in?(SEATS_TYPES)

            error_params = []
            unless options[:subscription_type].in?(SUBSCRIPTION_TYPES)
              error_params << "subscription: #{options[:subscription_type]}"
            end

            error_params << "seats:#{options[:seats_type]}" unless options[:seats_type].in?(SEATS_TYPES)

            raise ArgumentError, "Unknown parameters: #{error_params.join(', ')}" if error_params.any?
          end

          def value
            duo_seats_data(options[:subscription_type], options[:seats_type])
          end

          private

          def duo_seats_data(subscription_type, seats_type)
            add_ons = case subscription_type
                      when "pro"
                        GitlabSubscriptions::AddOnPurchase.for_gitlab_duo_pro
                      when "enterprise"
                        GitlabSubscriptions::AddOnPurchase.for_duo_enterprise
                      when "amazon_q"
                        GitlabSubscriptions::AddOnPurchase.for_duo_amazon_q
                      end

            active_duo = add_ons.active.first

            case seats_type
            when "purchased"
              active_duo&.quantity
            when "assigned"
              active_duo&.assigned_users&.count
            end
          end
        end
      end
    end
  end
end
