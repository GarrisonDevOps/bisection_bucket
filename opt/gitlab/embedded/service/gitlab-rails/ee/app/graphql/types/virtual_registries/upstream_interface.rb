# frozen_string_literal: true

module Types
  module VirtualRegistries
    module UpstreamInterface
      include Types::BaseInterface

      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the upstream registry.',
        experiment: { milestone: '18.1' }

      field :url, GraphQL::Types::String, null: false,
        description: 'URL of the upstream registry.',
        experiment: { milestone: '18.1' }

      field :cache_validity_hours, GraphQL::Types::Int, null: false,
        description: 'Time before the cache expires for the upstream registry.',
        experiment: { milestone: '18.1' }

      field :name, GraphQL::Types::String, null: false,
        description: 'Name of the upstream registry.',
        experiment: { milestone: '18.1' }

      field :description, GraphQL::Types::String, null: true,
        description: 'Description of the upstream registry.',
        experiment: { milestone: '18.1' }

      field :registries_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '18.6' },
        description: 'Number of registries using the upstream.'
    end
  end
end
