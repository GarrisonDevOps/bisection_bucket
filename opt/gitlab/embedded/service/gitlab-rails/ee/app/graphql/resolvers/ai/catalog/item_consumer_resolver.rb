# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ItemConsumerResolver < BaseResolver
        description 'Find a single AI Catalog item consumer by ID.'

        type ::Types::Ai::Catalog::ItemConsumerType, null: true

        argument :id,
          ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
          required: true,
          description: 'Global ID of the AI Catalog item consumer.'

        def resolve(id:)
          ::GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
