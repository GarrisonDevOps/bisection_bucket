# frozen_string_literal: true

module Ci
  module PipelineCreation
    class DropNotRunnableBuildsService
      include ::Gitlab::Utils::StrongMemoize

      def initialize(pipeline)
        @pipeline = pipeline

        @runners_availability = ::Gitlab::Ci::RunnersAvailabilityChecker.instance_for(pipeline.project)
      end

      ##
      # We want to run this service exactly once,
      # before the first pipeline processing call
      #
      def execute
        return unless pipeline.created?

        drop_non_matching_jobs
      end

      private

      attr_reader :pipeline
      attr_reader :runners_availability

      delegate :project, to: :pipeline

      def drop_non_matching_jobs
        builds_to_drop = {}

        build_matchers.each do |matcher|
          result = runners_availability.check(matcher)
          next if result.available?

          builds_to_drop[result.drop_reason] ||= []
          builds_to_drop[result.drop_reason] |= matcher.build_ids
        end

        builds_to_drop.each { |drop_reason, build_ids| drop_all_builds(build_ids, drop_reason) }
      end

      def build_matchers
        pipeline.build_matchers
      end
      strong_memoize_attr :build_matchers

      ##
      # We skip pipeline processing until we drop all required builds. Otherwise
      # as we drop the first build, the remaining builds to be dropped could
      # transition to other states by `PipelineProcessWorker` running async.
      #
      def drop_all_builds(build_ids, failure_reason)
        return if build_ids.empty?

        builds = pipeline.builds.id_in(build_ids).to_a
        preload_pending_states(builds)

        builds.each do |build|
          build.drop!(failure_reason, skip_pipeline_processing: true)
        end
      end

      def preload_pending_states(builds)
        ActiveRecord::Associations::Preloader.new(records: builds, associations: :pending_state).call
      end
    end
  end
end
