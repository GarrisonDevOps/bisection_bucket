# frozen_string_literal: true

module Geo
  module Console
    # rubocop:disable CodeReuse/ActiveRecord -- this is a troubleshooting console
    class ShowVerificationFailuresForReplicatorClassAction < ReplicatorClassAction
      def name
        "Show top X verification failures for #{@replicator_class.replicable_title}"
      end

      def execute
        limit = get_limit_from_user(default: 10)

        @output_stream.puts "Total failed to verify: #{@replicator_class.registry_class.verification_failed.count}"
        @output_stream.puts ""
        @output_stream.puts "Showing top #{limit} verification failures for #{@replicator_class.replicable_title}:"
        @output_stream.puts ""

        counts = @replicator_class
          .registry_class
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
