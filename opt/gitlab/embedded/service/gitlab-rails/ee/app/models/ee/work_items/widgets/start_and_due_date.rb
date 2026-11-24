# frozen_string_literal: true

module EE
  module WorkItems
    module Widgets
      module StartAndDueDate
        include ::Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        class_methods do
          def sync_params
            %i[start_date_fixed start_date_is_fixed due_date_fixed due_date_is_fixed]
          end
        end

        override :can_rollup?
        def can_rollup?
          work_item&.work_item_type&.allowed_child_types(resource_parent: work_item&.resource_parent).present?
        end
        strong_memoize_attr :can_rollup?

        def start_date_sourcing_work_item
          rollupable_dates.start_date_sourcing_work_item
        end

        def start_date_sourcing_milestone
          rollupable_dates.start_date_sourcing_milestone
        end

        def due_date_sourcing_work_item
          rollupable_dates.due_date_sourcing_work_item
        end

        def due_date_sourcing_milestone
          rollupable_dates.due_date_sourcing_milestone
        end
      end
    end
  end
end
