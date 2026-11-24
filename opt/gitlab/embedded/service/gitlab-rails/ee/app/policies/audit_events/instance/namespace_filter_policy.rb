# frozen_string_literal: true

module AuditEvents
  module Instance
    class NamespaceFilterPolicy < ::BasePolicy
      delegate { :global }
    end
  end
end
