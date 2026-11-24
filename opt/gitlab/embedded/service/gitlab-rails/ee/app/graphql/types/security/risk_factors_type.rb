# frozen_string_literal: true

module Types
  module Security
    class RiskFactorsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'RiskFactors'
      description 'Risk factors contributing to the total risk score'

      field :vulnerabilities_average_score, Types::Security::VulnerabilityAverageScoreFactorType,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Factor based on average vulnerability score.'
    end
  end
end
