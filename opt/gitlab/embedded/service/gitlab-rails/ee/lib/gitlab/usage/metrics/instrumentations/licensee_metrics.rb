# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class LicenseeMetrics < ::Gitlab::Usage::Metrics::Instrumentations::GenericMetric
          value do
            {
              "Name" => license&.licensee_name,
              "Company" => license&.licensee_company,
              "Email" => license&.licensee_email
            }
          end

          def license
            ::License.current if ::License.current&.license?
          end
        end
      end
    end
  end
end
