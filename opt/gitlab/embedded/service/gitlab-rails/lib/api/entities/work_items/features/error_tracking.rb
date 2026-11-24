# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class ErrorTracking < Grape::Entity
          expose :sentry_issue_identifier, as: :identifier,
            documentation: {
              type: 'Integer', example: 12345,
              desc: 'ID of the Sentry issue (error) linked to the work item. ' \
                'Null if the work item is not linked to a Sentry error.'
            },
            expose_nil: true
        end
      end
    end
  end
end
