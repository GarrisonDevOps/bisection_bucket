# frozen_string_literal: true

module Geo
  module Console
    # rubocop:disable CodeReuse/ActiveRecord -- this is a troubleshooting console
    class ShowPrimaryChecksumFailuresForReplicatorClassAction < ReplicatorClassAction
      def name
        "Show top X primary checksum failures for #{@replicator_class.replicable_title}"
      end

      def execute
        limit = get_limit_from_user(default: 10)

        checksum_failed_count = @replicator_class.model.verification_failed.count
        @output_stream.puts "Total failed to checksum on the primary: #{checksum_failed_count}"
        @output_stream.puts ""
        @output_stream.puts "Showing top #{limit} primary checksum failures for #{@replicator_class.replicable_title}:"
        @output_stream.puts ""

        counts = @replicator_class
          .model
          .verification_failed
          .group(:verification_failure)
          .limit(limit)
          .order("count_all DESC")
          .count

        PP.pp(counts, @output_stream)
        @output_stream.puts ""
      end
    end
    # rubocop:enable CodeReuse/ActiveRecord
  end
end
