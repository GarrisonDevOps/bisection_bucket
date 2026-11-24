# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module SavedViews
        module UnionedFilterInputType
          extend ActiveSupport::Concern

          prepended do
            argument :custom_field,
              [::Types::WorkItems::Widgets::CustomFieldFilterInputType],
              required: false,
              description: 'Filter value for unioned custom field filter.'
          end
        end
      end
    end
  end
end
