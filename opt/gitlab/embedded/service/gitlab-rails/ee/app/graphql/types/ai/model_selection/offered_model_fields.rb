# frozen_string_literal: true

module Types
  module Ai
    module ModelSelection
      module OfferedModelFields
        extend ActiveSupport::Concern

        included do
          field :ref, GraphQL::Types::String, null: false,
            description: 'Identifier for the offered model.'

          field :name, GraphQL::Types::String, null: false,
            description: 'Humanized name for the offered model, e.g "Chat GPT 4o".'

          field :model_provider, GraphQL::Types::String, null: true,
            experiment: { milestone: '18.6' },
            description: 'Provider for the model, e.g "OpenAI".'

          field :model_description, GraphQL::Types::String, null: true,
            experiment: { milestone: '18.7' },
            description: 'Brief description of the model, e.g "Fast, cost-effective responses".'

          field :cost_indicator, GraphQL::Types::String, null: true,
            experiment: { milestone: '18.7' },
            description: 'Presentational cost indicator for model usage, e.g "$", "$$", "$$$".'
        end
      end
    end
  end
end
