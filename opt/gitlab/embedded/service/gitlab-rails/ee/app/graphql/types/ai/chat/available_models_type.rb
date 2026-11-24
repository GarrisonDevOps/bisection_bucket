# frozen_string_literal: true

module Types
  module Ai
    module Chat
      # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
      class AvailableModelsType < Types::BaseObject
        graphql_name 'AvailableModels'
        description 'Available models for Duo Agentic Chat'

        field :default_model, ::Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'Default LLM for Duo Agentic Chat.'

        field :selectable_models, [Types::Ai::ModelSelection::OfferedModelType],
          null: true,
          description: "LLMs compatible with Duo Agentic Chat."

        field :pinned_model, ::Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'Pinned model for Duo Agentic Chat if set via feature settings.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
