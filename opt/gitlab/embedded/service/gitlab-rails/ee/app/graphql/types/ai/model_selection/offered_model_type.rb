# frozen_string_literal: true

module Types
  module Ai
    module ModelSelection
      # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
      class OfferedModelType < ::Types::BaseObject
        graphql_name 'AiModelSelectionOfferedModel'
        description 'Model offered for Model Selection'
        include ::Types::Ai::ModelSelection::OfferedModelFields

        field :requires_paid_credits, GraphQL::Types::Boolean, null: true,
          experiment: { milestone: '19.5' },
          description: 'Whether GitLab Credits must be purchased before this model ' \
            'can be used on the current namespace or instance.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
