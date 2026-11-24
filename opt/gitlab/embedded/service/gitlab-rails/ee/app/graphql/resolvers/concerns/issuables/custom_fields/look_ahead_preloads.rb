# frozen_string_literal: true

module Issuables
  module CustomFields
    module LookAheadPreloads
      private

      def unconditional_includes
        [:namespace]
      end

      def custom_field_preloads
        {
          created_by: [:created_by],
          updated_by: [:updated_by],
          select_options: [:select_options],
          work_item_types: [:work_item_type_custom_fields]
        }
      end
    end
  end
end
