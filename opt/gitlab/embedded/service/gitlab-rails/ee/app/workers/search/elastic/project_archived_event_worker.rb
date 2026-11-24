# frozen_string_literal: true

module Search
  module Elastic
    class ProjectArchivedEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Worker
      prepend ::Geo::SkipSecondary

      data_consistency :delayed
      urgency :low
      pause_control :advanced_search
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      defer_on_database_health_signal :gitlab_main, [:projects, :project_namespaces], 10.minutes

      def handle_event(event)
        return true unless Gitlab::CurrentSettings.elasticsearch_indexing?

        project = Project.find_by_id(event.data[:project_id])
        return if project.nil?

        project.maintain_elasticsearch_update(updated_attributes: ['archived']) if project.use_elasticsearch?
      end
    end
  end
end
