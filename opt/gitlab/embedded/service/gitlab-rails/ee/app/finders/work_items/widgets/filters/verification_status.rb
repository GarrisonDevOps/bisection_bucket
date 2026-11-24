# frozen_string_literal: true

module WorkItems
  module Widgets
    module Filters
      class VerificationStatus
        def self.filter(relation, params)
          verification_status = params.dig(:verification_status_widget, :verification_status)

          return relation unless verification_status

          relation = relation.with_issue_type(:requirement)

          if verification_status == 'missing'
            relation.without_test_reports
          else
            relation.with_last_test_report_state(verification_status)
          end
        end
      end
    end
  end
end
