# frozen_string_literal: true

module WorkItems
  module Lifecycles
    module LookAheadPreloads
      extend ActiveSupport::Concern
      include ::LooksAhead

      private

      def preloads
        {
          default_open_status: [:default_open_status],
          default_closed_status: [:default_closed_status],
          default_duplicate_status: [:default_duplicate_status],
          work_item_types: [:type_custom_lifecycles],
          statuses: [:statuses]
        }
      end
    end
  end
end
