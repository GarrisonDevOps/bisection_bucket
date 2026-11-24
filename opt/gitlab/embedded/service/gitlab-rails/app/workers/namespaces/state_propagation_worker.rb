# frozen_string_literal: true

module Namespaces
  class StatePropagationWorker
    include ApplicationWorker

    data_consistency :sticky

    queue_namespace :namespaces
    feature_category :groups_and_projects
    urgency :low
    defer_on_database_health_signal :gitlab_main, [:namespaces], 1.minute
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
    concurrency_limit -> { 200 }

    def perform(namespace_id)
      Namespaces::StatePropagationService.new(namespace_id).execute
    end
  end
end
