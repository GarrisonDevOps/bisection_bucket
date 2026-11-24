# frozen_string_literal: true

module Geo
  class EventLog < ApplicationRecord
    include Geo::Model

    EVENT_CLASSES = %w[Geo::CacheInvalidationEvent
      Geo::Event].freeze

    belongs_to :cache_invalidation_event,
      class_name: 'Geo::CacheInvalidationEvent',
      foreign_key: :cache_invalidation_event_id

    belongs_to :geo_event,
      class_name: 'Geo::Event',
      foreign_key: :geo_event_id,
      inverse_of: :geo_event_log

    def self.latest_event
      order(id: :desc).first
    end

    def self.next_unprocessed_event
      last_processed = Geo::EventLogState.last_processed
      return first unless last_processed

      find_by('id > ?', last_processed.event_id)
    end

    def self.event_classes
      EVENT_CLASSES.map(&:constantize)
    end

    def self.includes_events
      includes(reflections.keys)
    end

    def event
      cache_invalidation_event || geo_event
    end

    def project_id
      event.try(:project_id)
    end
  end
end
