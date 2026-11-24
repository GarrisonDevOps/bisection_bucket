# frozen_string_literal: true

module AuditEvents
  module Streaming
    module HTTP
      class NamespaceFilterPolicy < ::BasePolicy
        delegate { @subject.external_audit_event_destination.group }
      end
    end
  end
end
