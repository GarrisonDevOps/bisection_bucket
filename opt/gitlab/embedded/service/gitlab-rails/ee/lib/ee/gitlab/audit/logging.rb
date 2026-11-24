# frozen_string_literal: true

module EE
  module Gitlab
    module Audit
      module Logging
        extend ::Gitlab::Utils::Override

        override :log_events
        def log_events(event_class, events)
          super.tap do |created_events|
            ::AuditEvents::ComplianceViolationScheduler.new(created_events).execute
          end
        end
      end
    end
  end
end
