# frozen_string_literal: true

# This service is the last part of the generalized mechanic for orchestrating large exports.
#
# It's responsibility is checking if the final export content can be generated and delegating
# it to the relevant service if so.

module Gitlab
  module SegmentedExport
    class FinalizerService
      def initialize(export)
        @export = export
      end

      def execute
        if export.timed_out?
          fail_and_cleanup_export
        elsif can_be_finalized?
          finalize_export
        elsif needs_to_be_rescheduled?
          reschedule_finalization_work
        end
      end

      private

      attr_reader :export

      def fail_and_cleanup_export
        # The export may already be finished or failed (e.g. a segment failed). The state
        # machine only allows `failed` from created/running, so skip it to avoid raising.
        # Keep an existing `expires_at` so a late finalisation run doesn't push deletion back.
        export.failed! unless export.completed?
        export.schedule_export_deletion unless export.expires_at
      end

      def can_be_finalized?
        all_export_parts_present? && export.running?
      end

      def needs_to_be_rescheduled?
        export.running?
      end

      def all_export_parts_present?
        export.export_parts.all? { |part| part.file.present? }
      end

      def finalize_export
        export.export_service.finalise_segmented_export
      end

      def reschedule_finalization_work
        Gitlab::Export::SegmentedExportFinalisationWorker.perform_in(10.seconds, export.to_global_id)
      end
    end
  end
end
