# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module UnionedWorkItemFilterInputType
        extend ActiveSupport::Concern

        prepended do
          argument :custom_field, [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
            required: false,
            experiment: { milestone: '18.4' },
            description: 'Filter custom fields by one of the given values.'
        end
      end
    end
  end
end
