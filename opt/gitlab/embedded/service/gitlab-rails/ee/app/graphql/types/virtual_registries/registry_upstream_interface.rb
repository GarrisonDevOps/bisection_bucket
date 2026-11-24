# frozen_string_literal: true

module Types
  module VirtualRegistries
    module RegistryUpstreamInterface
      include Types::BaseInterface

      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the registry upstream.',
        experiment: { milestone: '18.2' }

      field :position, GraphQL::Types::Int, null: false,
        description: 'Position of the upstream registry in an ordered list.',
        experiment: { milestone: '18.2' }
    end
  end
end
