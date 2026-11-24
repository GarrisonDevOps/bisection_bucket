# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class SchedulingWorker
        include ApplicationWorker
        include CronjobQueue
        prepend ::Geo::SkipSecondary

        pause_control :active_context
        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        idempotent!
        urgency :low
        loggable_arguments 0
        defer_on_database_health_signal :gitlab_main,
          [:p_ai_active_context_code_enabled_namespaces, :p_ai_active_context_code_repositories],
          10.minutes

        def perform(task = nil)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          return initiate if task.nil?

          SchedulingService.execute(task)
        end

        private

        def initiate
          SchedulingService::TASKS.each do |task|
            with_context(related_class: self.class) { self.class.perform_async(task.first.to_s) }
          end
        end
      end
    end
  end
end
