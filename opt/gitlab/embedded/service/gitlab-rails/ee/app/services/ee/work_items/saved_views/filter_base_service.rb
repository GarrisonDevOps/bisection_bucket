# frozen_string_literal: true

module EE
  module WorkItems
    module SavedViews
      module FilterBaseService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class_methods do
          extend ::Gitlab::Utils::Override

          override :static_filters
          def static_filters
            super + %i[health_status_filter iteration_wildcard_id weight weight_wildcard_id]
          end

          override :static_negated_filters
          def static_negated_filters
            super + %i[health_status_filter weight iteration_wildcard_id]
          end
        end
      end
    end
  end
end
