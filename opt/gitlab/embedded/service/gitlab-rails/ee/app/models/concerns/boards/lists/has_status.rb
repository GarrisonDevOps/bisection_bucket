# frozen_string_literal: true

module Boards
  module Lists
    module HasStatus
      include ::WorkItems::Statuses::SharedConstants
      extend ActiveSupport::Concern

      included do
        scope :with_open_status_categories, -> {
          open_categories = CATEGORIES_STATE[:open]

          includes(:custom_status).where(
            "system_defined_status_identifier IS NOT NULL OR custom_status_id IS NOT NULL"
          ).select do |list|
            status = list.status
            status.category&.to_sym&.in?(open_categories)
          end
        }
      end
    end
  end
end
