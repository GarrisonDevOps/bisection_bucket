# frozen_string_literal: true

module Types
  module Security
    class RiskRatingEnum < BaseEnum
      graphql_name 'RiskRating'
      description 'Risk rating levels based on score ranges'

      value 'LOW', value: 'low', description: 'Low risk (0-25).'
      value 'MEDIUM', value: 'medium', description: 'Medium risk (26-50).'
      value 'HIGH', value: 'high', description: 'High risk (51-75).'
      value 'CRITICAL', value: 'critical', description: 'Critical risk (76-100).'
      value 'UNKNOWN', value: 'unknown', description: 'Unknown risk level.'
    end
  end
end
