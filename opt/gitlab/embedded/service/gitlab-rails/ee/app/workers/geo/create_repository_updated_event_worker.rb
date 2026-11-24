# frozen_string_literal: true

module Geo
  class CreateRepositoryUpdatedEventWorker
    include ApplicationWorker
    include Gitlab::EventStore::Subscriber
    include ::GeoQueue

    data_consistency :always

    idempotent!

    def handle_event(event)
      project = Project.find_by_id(event.data[:project_id])
      return unless project

      project.repository.log_geo_updated_event
    end
  end
end
