# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Blocking issues are EE-only; the implementation lives in the EE module.
    class RecountBlockingIssuesCount < BatchedMigrationJob
      cursor :id

      feature_category :portfolio_management

      def perform; end
    end
  end
end

Gitlab::BackgroundMigration::RecountBlockingIssuesCount.prepend_mod
