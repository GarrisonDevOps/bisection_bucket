# frozen_string_literal: true

module Geo
  # Module that defines event constants for replicators.
  module ReplicatorEvents
    extend ActiveSupport::Concern

    EVENT_CREATED = 'created'
    EVENT_DELETED = 'deleted'
    EVENT_UPDATED = 'updated'
  end
end
