# frozen_string_literal: true

module EE
  module WorkItems
    module Callbacks
      module StartAndDueDate
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        def after_update_commit
          ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
            .new(::WorkItem.id_in(work_item.id))
            .execute
        end

        private

        override :build_dates_source_attributes
        def build_dates_source_attributes
          return super if !params.key?(:is_fixed) || params[:is_fixed]

          { start_date_is_fixed: false, due_date_is_fixed: false }
            .merge(rolledup_attributes_for(:start_date))
            .merge(rolledup_attributes_for(:due_date))
        end

        def rolledup_attributes_for(field)
          finder.attributes_for(field).slice(
            field,
            :"#{field}_sourcing_milestone_id",
            :"#{field}_sourcing_work_item_id"
          )
        end

        def finder
          @finder ||= ::WorkItems::Widgets::RolledupDatesFinder.new(work_item)
        end
      end
    end
  end
end
