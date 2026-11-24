# frozen_string_literal: true

module Resolvers
  module Security
    class ScanProfileProjectStatusesResolver < BaseResolver
      include LooksAhead

      type [::Types::Security::ScanProfileProjectStatusType], null: true

      def resolve_with_lookahead
        apply_lookahead(object.security_scan_profile_project_statuses.with_not_deleted_scan_profile)
      end

      private

      def preloads
        {
          scan_profile: [:scan_profile],
          [:scan_profile, :triggers] => [{ scan_profile: :scan_profile_triggers }]
        }
      end
    end
  end
end
