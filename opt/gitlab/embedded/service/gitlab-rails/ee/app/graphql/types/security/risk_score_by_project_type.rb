# frozen_string_literal: true

module Types
  module Security
    class RiskScoreByProjectType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer
      graphql_name 'RiskScoreByProject'
      description 'Risk score information for a specific project.'

      field :project, Types::ProjectType,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Risk score belongs to the project.'

      field :score, GraphQL::Types::Float,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Risk score for the project.'

      field :rating, Types::Security::RiskRatingEnum,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Risk rating for the project.'
    end
  end
end
