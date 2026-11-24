# frozen_string_literal: true

module Geo
  class Event < ApplicationRecord
    include Geo::Model
    include Geo::Eventable

    has_one :geo_event_log, class_name: 'Geo::EventLog', foreign_key: :geo_event_id

    scope :for_replicable, ->(name) { where(replicable_name: name) }
  end
end
