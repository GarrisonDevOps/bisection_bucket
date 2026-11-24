# frozen_string_literal: true

module EE
  module Namespace # rubocop:disable Gitlab/BoundedContexts -- Existing module
    module PackageSetting
      extend ActiveSupport::Concern

      prepended do
        validates :audit_events_enabled, inclusion: { in: [true, false] }

        scope :with_audit_events_enabled, -> { where(audit_events_enabled: true) }
      end
    end
  end
end
