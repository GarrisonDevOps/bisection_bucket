# frozen_string_literal: true

module AuditEvents
  module Instance
    class ExternalStreamingDestinationPolicy < ::BasePolicy
      delegate { :global }
    end
  end
end
