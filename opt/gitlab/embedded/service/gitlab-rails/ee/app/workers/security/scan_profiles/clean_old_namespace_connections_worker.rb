# frozen_string_literal: true

module Security
  module ScanProfiles
    class CleanOldNamespaceConnectionsWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      deduplicate :until_executed
      feature_category :security_testing_configuration

      def perform(group_id, traverse_hierarchy = true)
        return unless group_id

        CleanOldNamespaceConnectionsService.execute(group_id, traverse_hierarchy)
      end
    end
  end
end
