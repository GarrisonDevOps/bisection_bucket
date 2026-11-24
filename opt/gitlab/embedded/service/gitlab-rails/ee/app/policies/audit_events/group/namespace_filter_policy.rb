# frozen_string_literal: true

module AuditEvents
  module Group
    class NamespaceFilterPolicy < ::BasePolicy
      delegate { @subject.external_streaming_destination.group }
    end
  end
end
