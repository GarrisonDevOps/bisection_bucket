# frozen_string_literal: true

module Geo
  class EventWorker
    include ApplicationWorker
    include GeoQueue

    idempotent!
    data_consistency :sticky
    sidekiq_options retry: 3, dead: true
    loggable_arguments 0, 1, 2

    def perform(replicable_name, event_name, payload)
      Labkit::Correlation::CorrelationId.use_id(correlation_id(payload)) do
        Geo::EventService.new(replicable_name, event_name, payload).execute
      end
    end

    private

    def correlation_id(payload)
      payload.fetch("correlation_id", Labkit::Correlation::CorrelationId.current_or_new_id)
    end
  end
end
