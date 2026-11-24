# frozen_string_literal: true

module Namespaces
  class CascadeWebBasedCommitSigningEnabledWorker
    include ApplicationWorker

    feature_category :source_code_management

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    defer_on_database_health_signal :gitlab_main, [:namespace_settings, :project_settings], 1.minute

    def perform(group_id)
      group = Group.find_by_id(group_id)
      return unless group

      web_based_commit_signing_enabled = group.namespace_settings.web_based_commit_signing_enabled

      ::Namespaces::CascadeWebBasedCommitSigningEnabledService.new(web_based_commit_signing_enabled).execute(group)
    end
  end
end
