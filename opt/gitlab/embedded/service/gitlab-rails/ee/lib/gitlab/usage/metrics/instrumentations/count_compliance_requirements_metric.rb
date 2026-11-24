# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountComplianceRequirementsMetric < DatabaseMetric
          METRIC_TYPES = %w[with_controls with_policies].freeze

          def initialize(metric_definition)
            super

            return if options[:metric_type].in?(METRIC_TYPES)

            raise ArgumentError,
              "Unknown metric type: #{options[:metric_type]}"
          end

          operation :distinct_count, column: 'compliance_requirements.id'

          relation do |options|
            base = ::ComplianceManagement::ComplianceFramework::ComplianceRequirement

            case options[:metric_type]
            when 'with_controls'
              base.joins(:compliance_requirements_controls)
            when 'with_policies'
              base.joins(:compliance_framework_security_policies)
            end
          end

          start { ::ComplianceManagement::ComplianceFramework::ComplianceRequirement.minimum(:id) }
          finish { ::ComplianceManagement::ComplianceFramework::ComplianceRequirement.maximum(:id) }
        end
      end
    end
  end
end
