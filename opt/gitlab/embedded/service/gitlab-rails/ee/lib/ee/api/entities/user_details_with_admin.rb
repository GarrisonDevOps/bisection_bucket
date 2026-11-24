# frozen_string_literal: true

module EE
  module API
    module Entities
      module UserDetailsWithAdmin
        extend ActiveSupport::Concern

        prepended do
          expose :plan, documentation: {
            type: 'String', desc: 'Subscription plan of the personal namespace of the user.'
          } do |user|
            user.namespace.try(:gitlab_subscription)&.plan_name
          end

          expose :trial, documentation: {
            type: 'Boolean', desc: 'If `true`, the personal namespace of the user is on a trial.'
          } do |user|
            user.namespace.try(:trial?)
          end
        end
      end
    end
  end
end
