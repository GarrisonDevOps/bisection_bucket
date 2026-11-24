# frozen_string_literal: true

module Types
  module Security
    module Ascp
      class SeverityEnum < BaseEnum
        graphql_name 'AscpSeverity'
        description 'Severity levels for ASCP security guidelines'

        value 'LOW', value: 'low', description: 'Low severity.'
        value 'MEDIUM', value: 'medium', description: 'Medium severity.'
        value 'HIGH', value: 'high', description: 'High severity.'
        value 'CRITICAL', value: 'critical', description: 'Critical severity.'
      end
    end
  end
end
