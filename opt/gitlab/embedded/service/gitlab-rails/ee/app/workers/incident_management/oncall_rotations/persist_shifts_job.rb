# frozen_string_literal: true

module IncidentManagement
  module OncallRotations
    # This worker saves On-call shifts while they are happening
    # as a historical record. This class does not account
    # for edits made to a rotation which might result in
    # conflicting shifts.
    class PersistShiftsJob
      include ApplicationWorker
      include Gitlab::Utils::StrongMemoize

      data_consistency :always

      sidekiq_options retry: 3

      idempotent!
      feature_category :incident_management

      def perform(rotation_id)
        @rotation = ::IncidentManagement::OncallRotation.find_by_id(rotation_id)
        return unless rotation && Gitlab::IncidentManagement.oncall_schedules_available?(rotation.project)

        generated_shifts = generate_shifts
        return unless generated_shifts.present?

        IncidentManagement::OncallShift.bulk_insert!(generated_shifts)
      end

      private

      attr_reader :rotation

      def generate_shifts
        ::IncidentManagement::OncallShiftGenerator
          .new(rotation)
          .for_timeframe(
            starts_at: shift_generation_start_time,
            ends_at: Time.current
          ).tap { |shifts| handle_conflicts(shifts) }
      end

      # To avoid generating shifts in the past, which could lead to unnecessary processing,
      # we get the latest of rotation created time, rotation start time,
      # rotation edit time, or the most recent shift.
      def shift_generation_start_time
        [
          rotation.created_at,
          rotation.updated_at,
          rotation.starts_at,
          last_shift_end_time
        ].compact.max
      end

      def last_shift_end_time
        rotation.shifts.order_starts_at_desc.first&.ends_at
      end
      strong_memoize_attr :last_shift_end_time

      # If a generated shift starts before the last persisted shift ends,
      # something has gone amiss in shift calculation/config. But
      # OncallUsersFinder will always defer to saved shift records,
      # so this job should also respect the saved records.
      def handle_conflicts(shifts)
        return unless shifts.first && last_shift_end_time

        shifts.first.starts_at = [shifts.first.starts_at, last_shift_end_time].max
      end
    end
  end
end
