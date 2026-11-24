# frozen_string_literal: true

module EE
  module Mutations
    module UserPreferences # rubocop:disable Gitlab/BoundedContexts -- EE extension of existing class
      module Update
        extend ActiveSupport::Concern

        prepended do
          argument :duo_default_namespace_id,
            GraphQL::Types::Int,
            required: false,
            description: 'Default namespace context for Duo features when namespace can not be inferred.'

          argument :knowledge_graph_governing_namespace_id,
            GraphQL::Types::Int,
            required: false,
            description: 'Governing and billing namespace for Orbit.'
        end
      end
    end
  end
end
