# frozen_string_literal: true

module EE
  module Packages
    module Package
      extend ActiveSupport::Concern

      PROCESSING_TO_DEFAULT = ::Packages::Package.statuses.invert.values_at(2, 0).freeze

      prepended do
        include ::Auditable

        after_commit :create_audit_event, on: %i[create update]

        private

        def create_audit_event
          return unless default?
          return if maven? && version.nil?
          return unless previously_new_record? || saved_change_to_status?
          return if saved_change_to_status? && saved_change_to_status != PROCESSING_TO_DEFAULT

          ::Packages::CreateAuditEventService.new(self).execute
        end
      end
    end
  end
end
