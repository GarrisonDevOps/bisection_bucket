# frozen_string_literal: true

# This service is a part of the generalized mechanic for orchestrating large exports
# in batches with parallel processing.
# It's responsibility is to generate intermediary export contents which then will be
# used to generate the final export.

module Gitlab
  module SegmentedExport
    class SegmentExporterService
      def initialize(export, segment_ids)
        @export = export
        @segment_ids = segment_ids
      end

      def execute
        export_parts.each { |export_part| export.export_service.export_segment(export_part) }

        # This is going to run the job over and over until it finalises.
        # This may use a lot of Redis and Sidekiq throughtput to effectively poll the
        # export state until finalisation can occur.
        # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/157695#note_1973854202
        Gitlab::Export::SegmentedExportFinalisationWorker.perform_async(export.to_global_id)
      end

      private

      attr_reader :export, :segment_ids

      delegate :export_service, to: :export, private: true

      def export_parts
        export.export_parts.id_in(segment_ids)
      end
    end
  end
end
