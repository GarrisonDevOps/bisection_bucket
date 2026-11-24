# frozen_string_literal: true

module EE
  module Packages
    module MarkPackageForDestructionService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        super.tap do |response|
          if response.success?
            user = current_user

            package.run_after_commit_or_now do
              ::Packages::CreateAuditEventService
                .new(self, current_user: user, event_name: 'package_registry_package_deleted')
                .execute
            end
          end
        end
      end
    end
  end
end
