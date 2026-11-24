# frozen_string_literal: true

module Search
  module Elastic
    class ReindexingService
      # skip projects, all namespace and project data is handled by `namespaces` task
      DEFAULT_OPTIONS = { 'skip' => %w[projects] }.freeze

      attr_reader :delay

      def self.execute(...)
        new(...).execute
      end

      def initialize(delay: 0)
        @delay = delay
      end

      def execute
        initial_task = Search::Elastic::TriggerIndexingWorker::INITIAL_TASK.to_s
        Search::Elastic::TriggerIndexingWorker.perform_in(delay, initial_task, options)
      end

      private

      def options
        DEFAULT_OPTIONS.dup.tap do |o|
          o['skip'] = o['skip'] - ['projects'] if ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?
        end
      end
    end
  end
end
