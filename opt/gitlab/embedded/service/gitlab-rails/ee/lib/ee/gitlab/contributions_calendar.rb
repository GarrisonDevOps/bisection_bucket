# frozen_string_literal: true

module EE
  module Gitlab
    module ContributionsCalendar
      extend ::Gitlab::Utils::Override

      def initialize(contributor, current_user = nil)
        super

        @groups = ::Users::ContributedGroupsFinder.new(contributor)
          .execute(current_user, include_private_contributions: @contributor.include_private_contributions?)
      end

      private

      override :collect_events_between
      def collect_events_between(start_time, end_time)
        group_events = group_events_created_between(start_time, end_time)
        epic_events = group_events.epics.for_action(%i[created closed reopened])
        group_note_events = group_events.for_action(:commented)

        super + [epic_events, group_note_events]
      end

      # rubocop: disable CodeReuse/ActiveRecord -- no need to move this to ActiveRecord model
      def group_events_created_between(start_time, end_time)
        contributed_group_ids = groups.distinct.pluck_primary_key.uniq

        contribution_events(start_time, end_time).where(group_id: contributed_group_ids)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
