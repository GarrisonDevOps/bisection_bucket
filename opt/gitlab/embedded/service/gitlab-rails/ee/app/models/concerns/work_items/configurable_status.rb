# frozen_string_literal: true

module WorkItems
  module ConfigurableStatus
    extend ActiveSupport::Concern

    include ::WorkItems::Statuses::SharedConstants

    def icon_name
      CATEGORY_ICONS[category.to_sym]
    end

    def state
      CATEGORIES_STATE.find { |state, categories| state if categories.include?(category.to_sym) }&.first
    end

    def hook_attrs
      {
        id: to_gid.to_s,
        name: name,
        category: category,
        description: description,
        color: color
      }
    end
  end
end
