# frozen_string_literal: true

module IncidentManagement
  module OncallSchedules
    class UpdateService < OncallSchedules::BaseService
      def execute(oncall_schedule)
        return error_no_license unless available?
        return error_no_permissions unless allowed?

        IncidentManagement::OncallSchedule.transaction do
          impacted_rotations = oncall_schedule.rotations.with_active_period

          update_shifts!(oncall_schedule, impacted_rotations)
          oncall_schedule.update!(params)
          update_rotations!(oncall_schedule, impacted_rotations)
        end

        success(oncall_schedule)
      rescue ActiveRecord::RecordInvalid => e
        error(e.record.errors.full_messages.to_sentence)
      rescue StandardError => e
        error(e.message)
      end

      private

      # Ensure shift history is accurate before touching #updated_at on the rotation
      def update_shifts!(oncall_schedule, rotations)
        return if oncall_schedule.timezone == params[:timezone]

        rotations.each do |rotation|
          IncidentManagement::OncallRotations::PersistShiftsJob.new.perform(rotation.id)
        end
      end

      # Converts & updates the active period to the new timezone
      # so the rotation is uninterrupted by the timezone change
      # Ex: 8:00 - 17:00 Europe/Berlin becomes 6:00 - 15:00 UTC
      def update_rotations!(oncall_schedule, rotations)
        return unless oncall_schedule.timezone_previously_changed?

        rotations.each do |rotation|
          start_time, end_time = format_active_period(rotation, *oncall_schedule.previous_changes[:timezone])

          # Skipping side-effects of OncallRotations::EditSerivce, as
          # we DON'T want to change the rotation's behavior
          rotation.update!(
            active_period_start: start_time,
            active_period_end: end_time
          )
        end
      end

      def format_active_period(rotation, old_timezone, new_timezone)
        rotation
          .active_period
          .for_date(Time.current.in_time_zone(old_timezone))
          .map { |time| time.in_time_zone(new_timezone).strftime('%H:%M') }
      end

      def error_no_permissions
        error(_('You have insufficient permissions to update an on-call schedule for this project'))
      end
    end
  end
end
