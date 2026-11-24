# frozen_string_literal: true

module EE
  module RepositoryImportWorker
    extend ::Gitlab::Utils::Override

    override :perform
    def perform(project_id)
      super
      return if project.nil?

      # Explicitly enqueue mirror for update so
      # that upstream remote is created and fetched
      project.import_state.force_import_job! if project.mirror? && !project.import_state.failed?
    end
  end
end
