# frozen_string_literal: true

module Auditable
  extend ActiveSupport::Concern
  include AfterCommitQueue

  # Use `after_commit: false` when you're already handling the transaction boundary
  def push_audit_event(event, after_commit: true)
    return unless ::Gitlab::Audit::EventQueue.active?

    if after_commit
      run_after_commit do
        ::Gitlab::Audit::EventQueue.push(event)
      end
    else
      ::Gitlab::Audit::EventQueue.push(event)
    end
  end

  def audit_details
    raise NotImplementedError, "#{self.class} does not implement #{__method__}"
  end
end
