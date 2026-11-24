# frozen_string_literal: true

module EE
  module Packages
    module MarkPackagesForDestructionService
      extend ::Gitlab::Utils::Override

      private

      override :after_marked_for_destruction
      def after_marked_for_destruction(packages)
        super
        send_audit_events(packages)
      end

      def send_audit_events(packages)
        ::Packages::CreateAuditEventsService.new(packages, current_user:).execute
      end
    end
  end
end
