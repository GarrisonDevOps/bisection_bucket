# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class AdHocIndexingWorker
        include ApplicationWorker
        include Ai::ActiveContext::Concerns::CodeEligibility
        prepend ::Geo::SkipSecondary

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:p_ai_active_context_code_repositories], 10.minutes

        def perform(project_id)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          project = Project.find_by_id(project_id)
          return false unless project

          existing_repository = Ai::ActiveContext::Code::Repository.for_project(project.id).first
          return false if existing_repository && !existing_repository.deleted?
          return false unless project_eligible_for_indexing?(project, force_cache_reload: true)

          if existing_repository
            existing_repository.update(state: :pending, delete_reason: nil, last_commit: nil)
            repository = existing_repository
          else
            repository = create_repository_record(project)
          end

          RepositoryIndexWorker.perform_async(repository.id)
        end

        private

        def create_repository_record(project)
          Ai::ActiveContext::Code::Repository.create(
            project_id: project.id,
            enabled_namespace_id: enabled_namespace_for_project(project).id,
            connection_id: active_connection.id,
            state: :pending
          )
        end
      end
    end
  end
end
