# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class GitlabSubscription < Grape::Entity
          expose :plan, documentation: { type: 'Hash' } do
            expose :plan_name, as: :code, documentation: { type: 'String' }
            expose :plan_title, as: :name, documentation: { type: 'String' }
            expose :trial, documentation: { type: 'Boolean' }
            expose :auto_renew, documentation: { type: 'Boolean' }
            expose :upgradable?, as: :upgradable, documentation: { type: 'Boolean' }
            expose :exclude_guests?, as: :exclude_guests, documentation: { type: 'Boolean' }
          end

          expose :usage, documentation: { type: 'Hash' } do
            expose :seats, as: :seats_in_subscription, documentation: { type: 'Integer' }
            expose :seats_in_use, documentation: { type: 'Integer' }
            expose :max_seats_used, documentation: { type: 'Integer' }
            expose :seats_owed, documentation: { type: 'Integer' }
          end

          expose :billing, documentation: { type: 'Hash' } do
            expose :start_date, as: :subscription_start_date, documentation: { type: 'Date' }
            expose :end_date, as: :subscription_end_date, documentation: { type: 'Date' }
            expose :trial_ends_on, documentation: { type: 'Date' }
          end
        end
      end
    end
  end
end
