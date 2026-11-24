# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class VerificationStatus < Grape::Entity
          # Values come from WorkItems::Widgets::VerificationStatus::STATUS_MAP and its 'unverified' fallback.
          expose :verification_status,
            documentation: {
              type: 'String', example: 'satisfied', values: %w[satisfied failed unverified],
              desc: "Result of the requirement's latest test report: `satisfied` if it passed, " \
                '`failed` if it failed, or `unverified` if there is no test report.'
            },
            expose_nil: true
        end
      end
    end
  end
end
