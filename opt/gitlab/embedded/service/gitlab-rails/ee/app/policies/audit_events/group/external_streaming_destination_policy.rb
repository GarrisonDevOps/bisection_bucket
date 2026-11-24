# frozen_string_literal: true

module AuditEvents
  module Group
    class ExternalStreamingDestinationPolicy < ::BasePolicy
      delegate { @subject.group }
    end
  end
end
