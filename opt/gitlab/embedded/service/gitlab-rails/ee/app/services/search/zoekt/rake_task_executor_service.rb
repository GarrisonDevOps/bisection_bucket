# frozen_string_literal: true

module Search
  module Zoekt
    class RakeTaskExecutorService
      TASKS = %i[
        disable
        estimate_storage
        health
        index
        info
        pause_indexing
        reindex_failed_projects
        reindex_projects
        resume_indexing
      ].freeze

      def initialize(logger:, options:)
        @logger = logger
        @options = options.with_indifferent_access
      end

      def execute(task)
        raise ArgumentError, "Unknown task: #{task}" unless TASKS.include?(task)
        raise NotImplementedError unless respond_to?(task, true)

        send(task) # rubocop:disable GitlabSecurity/PublicSend -- We control the list of tasks in the source code
      end

      private

      attr_reader :logger, :options

      def info
        InfoService.execute(logger: logger, options: options)
      end

      def health
        HealthService.execute(logger: logger, options: options)
      end

      def index
        indexing_settings_service.index
      end

      def disable
        indexing_settings_service.disable
      end

      def pause_indexing
        indexing_settings_service.pause_indexing
      end

      def resume_indexing
        indexing_settings_service.resume_indexing
      end

      def estimate_storage
        EstimateStorageService.execute(logger: logger)
      end

      def reindex_projects
        indexing_settings_service.reindex_projects
      end

      def reindex_failed_projects
        project_ids = options[:project_ids].presence
        indexing_settings_service.reindex_failed_projects(project_ids: project_ids)
      end

      def indexing_settings_service
        @indexing_settings_service ||= IndexingSettingsService.new(logger: logger)
      end
    end
  end
end
