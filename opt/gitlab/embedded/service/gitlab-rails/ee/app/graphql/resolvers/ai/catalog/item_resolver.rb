# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ItemResolver < BaseResolver
        description 'Find an AI Catalog item.'

        type ::Types::Ai::Catalog::ItemInterface, null: true

        argument :id,
          ::Types::GlobalIDType[::Ai::Catalog::Item],
          required: true,
          description: 'Global ID of the catalog item to find.'

        argument :show_soft_deleted,
          GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Whether to show the item if it has been soft-deleted. Defaults to `false`.'

        def resolve(id:, show_soft_deleted:)
          Gitlab::Graphql::Lazy.with_value(find_object(id: id)) do |item|
            next if item&.deleted? && show_soft_deleted == false

            item
          end
        end

        private

        def find_object(id:)
          GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
