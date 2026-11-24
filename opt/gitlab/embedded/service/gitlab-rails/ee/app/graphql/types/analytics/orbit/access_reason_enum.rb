# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class AccessReasonEnum < BaseEnum
        graphql_name 'OrbitAccessReason'
        description 'Cause of an Orbit access state that has more than one cause.'

        DESCRIPTIONS = {
          free_plan: 'Group is on a Free plan on GitLab.com.',
          no_license: 'Instance has no Orbit license.',
          no_access: 'Group has no Orbit access under the promo gate.',
          trial_expired: 'Trial reached its end date.',
          credits_exhausted: 'Trial ran out of credits before its end date.',
          plan: 'Access comes from the plan license.',
          promo_add_on: 'Access comes from the Orbit promo add-on.',
          beta: 'Access comes from the free-beta program.'
        }.freeze

        ::Analytics::Orbit::Access::REASONS.each do |reason|
          value reason.to_s.upcase,
            value: reason,
            description: DESCRIPTIONS.fetch(reason),
            experiment: { milestone: '19.5' }
        end
      end
    end
  end
end
