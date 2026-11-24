# frozen_string_literal: true

module Gitlab
  module EpicWorkItemSync
    class Diff
      BASE_ATTRIBUTES = %w[
        author_id
        closed_at
        closed_by_id
        confidential
        created_at
        description
        iid
        imported_from
        last_edited_at
        last_edited_by_id
        state_id
        title
        updated_by_id
      ].freeze

      ALLOWED_TIME_RANGE_S = 5.seconds

      # strict_equal: true
      #   We expect that a work item is fully synced with the epic, including all relations.
      # strict_equal: false
      #   Allows that relations are partially synced. For example when the backfill did not run yet but we already start
      #   creating related links. We only check against links that have a work item.
      def initialize(epic, work_item, strict_equal: false)
        @epic = epic
        @work_item = work_item
        @strict_equal = strict_equal
        @mismatched_attributes = []
      end

      def attributes
        check_base_attributes
        check_updated_at
        check_namespace

        check_color
        check_parent
        check_child_issues
        check_relative_position
        check_dates
        check_related_epic_links

        mismatched_attributes
      end

      private

      def check_base_attributes
        BASE_ATTRIBUTES.each do |attribute|
          next if epic.attributes[attribute] == work_item.attributes[attribute]

          mismatched_attributes.push(attribute)
        end
      end

      def check_updated_at
        return if (epic.updated_at - work_item.updated_at).abs < ALLOWED_TIME_RANGE_S

        mismatched_attributes.push("updated_at")
      end

      def check_namespace
        mismatched_attributes.push("namespace") if epic.group_id != work_item.namespace_id
      end

      def check_color
        return if epic.color == Epic::DEFAULT_COLOR && work_item.color.nil?
        return if epic.color == work_item.color&.color

        mismatched_attributes.push("color")
      end

      def check_parent
        return if epic.parent.nil? && work_item.work_item_parent.nil?
        return if epic.parent&.issue_id == work_item.work_item_parent&.id

        mismatched_attributes.push("parent_id")
      end

      # rubocop:disable CodeReuse/ActiveRecord -- temporary, this is to be removed once epic sync is done.
      def check_child_issues
        return if epic.epic_issues.blank? && work_item.child_links.blank?

        epic_issue_ids = epic.epic_issues.pluck(:issue_id).sort
        epic_work_item_issue_child_ids = work_item.child_links.joins(:work_item)
          .merge(WorkItem.with_issue_type(['issue']))
          .pluck(:work_item_id).sort

        return if epic_issue_ids == epic_work_item_issue_child_ids

        mismatched_attributes.push("epic_issue")
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def check_relative_position
        # if there is no parent_link there is nothing to compare with
        return if work_item.parent_link.blank?
        return if epic.relative_position == work_item.parent_link.relative_position

        mismatched_attributes.push("relative_position")
      end

      def check_dates
        work_item_dates_source = work_item.dates_source

        check_start_date_is_fixed(work_item_dates_source)
        check_start_date_fixed(work_item_dates_source)
        check_due_date_is_fixed(work_item_dates_source)
        check_due_date_fixed(work_item_dates_source)
        check_start_date(work_item_dates_source)
        check_due_date(work_item_dates_source)
        check_source_milestone(work_item_dates_source)
        check_source_epic(work_item_dates_source)
      end

      def check_start_date_is_fixed(dates_source)
        return if epic.start_date_is_fixed == dates_source&.start_date_is_fixed
        return if epic.start_date_is_fixed.nil? && dates_source.start_date_is_fixed == false

        mismatched_attributes.push("start_date_is_fixed")
      end

      def check_start_date_fixed(dates_source)
        return if epic.start_date_fixed == dates_source&.start_date_fixed

        mismatched_attributes.push("start_date_fixed")
      end

      def check_start_date(dates_source)
        return unless epic.start_date_is_fixed
        return if (epic.start_date_fixed == epic.start_date) && (epic.start_date_fixed == dates_source&.start_date)

        mismatched_attributes.push("start_date")
      end

      def check_due_date(dates_source)
        return unless epic.due_date_is_fixed
        return if (epic.due_date_fixed == epic.end_date) && (epic.due_date_fixed == dates_source&.due_date)

        mismatched_attributes.push("due_date")
      end

      def check_due_date_is_fixed(dates_source)
        return if epic.due_date_is_fixed == dates_source&.due_date_is_fixed
        return if epic.due_date_is_fixed.nil? && dates_source.due_date_is_fixed == false

        mismatched_attributes.push("due_date_is_fixed")
      end

      def check_due_date_fixed(dates_source)
        return if epic.due_date_fixed == dates_source&.due_date_fixed

        mismatched_attributes.push("due_date_fixed")
      end

      def check_source_milestone(dates_source)
        if epic.start_date_sourcing_milestone_id != dates_source&.start_date_sourcing_milestone_id
          mismatched_attributes.push("start_date_sourcing_milestone")
        end

        return if epic.due_date_sourcing_milestone_id == dates_source&.due_date_sourcing_milestone_id

        mismatched_attributes.push("due_date_sourcing_milestone")
      end

      def check_source_epic(dates_source)
        if epic.start_date_sourcing_epic&.issue_id != dates_source&.start_date_sourcing_work_item_id
          mismatched_attributes.push("start_date_sourcing_epic")
        end

        return if epic.due_date_sourcing_epic&.issue_id == dates_source&.due_date_sourcing_work_item_id

        mismatched_attributes.push("due_date_sourcing_epic")
      end

      def check_related_epic_links
        related_epic_issues = epic.unauthorized_related_epics

        related_epic_issue_ids = related_epic_issues.map(&:issue_id)
        related_work_item_ids = work_item.related_issues(authorize: false).joins(:sync_object).map(&:id) # rubocop:disable CodeReuse/ActiveRecord -- this is to be removed once epic sync is done.

        return if related_work_item_ids.sort == related_epic_issue_ids.sort

        mismatched_attributes.push("related_links")
      end

      attr_reader :epic, :work_item, :strict_equal
      attr_accessor :mismatched_attributes
    end
  end
end
