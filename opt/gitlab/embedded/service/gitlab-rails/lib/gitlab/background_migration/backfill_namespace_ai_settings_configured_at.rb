# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Adds the tracked keys missing from namespace_ai_settings.configured_at
    # with the backfill time. EE-only; see the EE module for the implementation.
    class BackfillNamespaceAiSettingsConfiguredAt < BatchedMigrationJob
      feature_category :compliance_management

      def perform; end
    end
  end
end

Gitlab::BackgroundMigration::BackfillNamespaceAiSettingsConfiguredAt.prepend_mod
