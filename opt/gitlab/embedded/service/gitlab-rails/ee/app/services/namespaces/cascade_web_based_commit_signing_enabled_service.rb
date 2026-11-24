# frozen_string_literal: true

module Namespaces
  class CascadeWebBasedCommitSigningEnabledService
    def initialize(web_based_commit_signing_enabled)
      @web_based_commit_signing_enabled = web_based_commit_signing_enabled
    end

    def execute(group)
      update_subgroups(group)
      update_projects(group)
    end

    private

    def update_subgroups(group)
      group.self_and_descendants.each_batch do |batch|
        namespace_ids = batch.pluck_primary_key
        NamespaceSetting.for_namespaces(namespace_ids)
          .update_all(web_based_commit_signing_enabled: @web_based_commit_signing_enabled)
      end
    end

    def update_projects(group)
      group.all_projects.each_batch do |batch|
        project_ids_to_update = batch.pluck_primary_key
        ProjectSetting.for_projects(project_ids_to_update)
          .update_all(web_based_commit_signing_enabled: @web_based_commit_signing_enabled)
      end
    end
  end
end
