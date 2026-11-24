# frozen_string_literal: true

module Resolvers
  module AuditEvents
    module Instance
      class StreamingDestinationsResolver < BaseResolver
        type [::Types::AuditEvents::Instance::StreamingDestinationType], null: true

        def resolve
          ::AuditEvents::Instance::ExternalStreamingDestination.all
        end
      end
    end
  end
end
