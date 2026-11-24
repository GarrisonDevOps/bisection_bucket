# frozen_string_literal: true

module AuditEvents
  module GroupStreamDestinationMappable
    extend ActiveSupport::Concern
    included do
      belongs_to :stream_destination, class_name: 'AuditEvents::Group::ExternalStreamingDestination', optional: true

      validates :stream_destination, uniqueness: { allow_nil: true }
    end

    def instance_level?
      false
    end
  end
end
