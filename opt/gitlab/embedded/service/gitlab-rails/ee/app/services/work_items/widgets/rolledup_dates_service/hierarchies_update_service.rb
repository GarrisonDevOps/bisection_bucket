# frozen_string_literal: true

module WorkItems
  module Widgets
    module RolledupDatesService
      class HierarchiesUpdateService
        BATCH_SIZE = 100

        def initialize(work_items)
          @work_items = work_items
          @finder = finder_class.new(@work_items)
        end

        # rubocop: disable CodeReuse/ActiveRecord -- complex update requires some query methods
        def execute
          return if @work_items.blank?

          @work_items.each_batch(of: BATCH_SIZE) do |batch|
            ensure_dates_sources_exist(batch)
            dates_source = ::WorkItems::DatesSource.work_items_in(batch)

            ::WorkItems::DatesSource.transaction do
              dates_source.where(start_date_is_fixed: false).update_all([
                %{ (start_date, start_date_sourcing_milestone_id, start_date_sourcing_work_item_id) = (?) },
                join_with_update(finder.minimum_start_date)
              ])

              dates_source.where(due_date_is_fixed: false).update_all([
                %{ (due_date, due_date_sourcing_milestone_id, due_date_sourcing_work_item_id) = (?) },
                join_with_update(finder.maximum_due_date)
              ])

              update_synced_epics(batch, dates_source)
            end

            update_parents(batch)
          end
        end

        private

        attr_reader :finder

        def ensure_dates_sources_exist(work_items)
          work_items
            .excluding(work_items.joins(:dates_source)) # exclude work items that already have a dates source
            .each(&:create_dates_source_from_current_dates)
        end

        def join_with_update(query)
          query.where("#{finder_class::UNION_TABLE_ALIAS}.parent_id = work_item_dates_sources.issue_id")
        end

        # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- the query already uses the batch limited in 100 items
        def update_parents(work_items)
          descendants = ::Gitlab::WorkItems::WorkItemHierarchy.new(work_items).descendants
          parent_ids = WorkItems::ParentLink
            .for_children(work_items)
            .where.not(work_item_parent_id: descendants)
            .pluck(:work_item_parent_id)
          return if parent_ids.blank?

          ::WorkItems::RolledupDates::UpdateMultipleRolledupDatesWorker.perform_async(parent_ids)
        end
        # rubocop: enable Database/AvoidUsingPluckWithoutLimit

        def finder_class
          ::WorkItems::Widgets::RolledupDatesFinder
        end

        def update_synced_epics(work_items, dates_sources)
          Epic
            .where(issue_id: work_items.select(:id))
            .update_all([
              %{(
                start_date,
                start_date_fixed,
                start_date_is_fixed,
                start_date_sourcing_milestone_id,
                start_date_sourcing_epic_id,
                end_date,
                due_date_fixed,
                due_date_is_fixed,
                due_date_sourcing_milestone_id,
                due_date_sourcing_epic_id
                ) = (?)
              },
              synced_epics_values(dates_sources)
            ])
        end

        def synced_epics_values(dates_sources)
          dates_sources
            .select(
              'work_item_dates_sources.start_date',
              'work_item_dates_sources.start_date_fixed',
              'work_item_dates_sources.start_date_is_fixed',
              'work_item_dates_sources.start_date_sourcing_milestone_id',
              'start_date_sourcing_epic.id',
              'work_item_dates_sources.due_date',
              'work_item_dates_sources.due_date_fixed',
              'work_item_dates_sources.due_date_is_fixed',
              'work_item_dates_sources.due_date_sourcing_milestone_id',
              'due_date_sourcing_epic.id'
            )
            .joins(<<~SQL)
              LEFT JOIN epics due_date_sourcing_epic
                ON work_item_dates_sources.due_date_sourcing_work_item_id = due_date_sourcing_epic.issue_id
            SQL
            .joins(<<~SQL)
              LEFT JOIN epics start_date_sourcing_epic ON
                work_item_dates_sources.start_date_sourcing_work_item_id = start_date_sourcing_epic.issue_id
            SQL
            .where('epics.issue_id = work_item_dates_sources.issue_id')
        end
        # rubocop: enable CodeReuse/ActiveRecord
      end
    end
  end
end
