# frozen_string_literal: true

module AuditEvents
  module InstanceStreamDestinationMappable
    extend ActiveSupport::Concern
    included do
      belongs_to :stream_destination, class_name: 'AuditEvents::Instance::ExternalStreamingDestination', optional: true

      validates :stream_destination, uniqueness: { allow_nil: true }
    end

    def instance_level?
      true
    end
  end
end
