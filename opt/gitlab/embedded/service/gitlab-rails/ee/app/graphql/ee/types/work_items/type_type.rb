# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module TypeType
        extend ActiveSupport::Concern

        prepended do
          field :enabled_by_default_for_new_namespaces, GraphQL::Types::Boolean,
            null: false,
            description: 'Whether the work item type is enabled by default when new child namespaces are created.',
            method: :enabled_by_default_for_new_namespaces?,
            experiment: { milestone: '19.0' }
        end
      end
    end
  end
end
