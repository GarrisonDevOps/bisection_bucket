# frozen_string_literal: true

module Types
  module Security
    class RiskScoreType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'RiskScore'
      description 'Total risk score information'

      field :score, GraphQL::Types::Float,
        null: false,
        experiment: { milestone: '18.4' },
        description: 'Overall risk score.'

      field :rating, Types::Security::RiskRatingEnum,
        null: false,
        experiment: { milestone: '18.4' },
        description: 'Overall risk rating.'

      field :factors, Types::Security::RiskFactorsType,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Risk factors contributing to the score.'

      field :project_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '18.5' },
        description: 'Total number of projects with risk scores.'

      field :by_project,
        ::Types::Security::RiskScoreByProjectType.connection_type,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Risk scores grouped by project.'
    end
  end
end
