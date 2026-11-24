# frozen_string_literal: true

class ProjectImportScheduleWorker
  include ApplicationWorker

  data_consistency :delayed

  idempotent!
  deduplicate :until_executed, ttl: 5.minutes, if_deduplicated: :reschedule_once

  feature_category :source_code_management
  sidekiq_options retry: 1
  loggable_arguments 1 # For the job waiter key
  log_bulk_perform_async!

  def perform(project_id)
    ::Gitlab::Mirror.untrack_scheduling(project_id)

    return if Gitlab::Database.read_only?

    project = Project.with_route.with_import_state.with_namespace.find_by_id(project_id)

    with_context(project: project) do
      unless project&.import_state
        log_extra_metadata_on_done(:mirroring_skipped, "No import state found for #{project_id}")
        next
      end

      if ::Import::Sync::Projects::WritePolicy.repository_mirroring_blocked?(project)
        log_extra_metadata_on_done(:mirroring_skipped, 'GitHub updates control repository mirroring')
        next
      end

      # Recover mirrors from canceled state by transitioning through failed.
      # This handles the case where a GitHub import was canceled on a project
      # that later became a mirror. Mirrors preserve import_data (unlike regular
      # imports), so they can be recovered by transitioning canceled to failed to scheduled.
      # See: https://gitlab.com/gitlab-org/gitlab/-/issues/539236
      if project.import_state.canceled?
        if project.mirror?
          project.import_state.mark_as_failed('Mirror recovering from canceled state')
          log_extra_metadata_on_done(:import_state_recovered, 'Recovered mirror from canceled state')
        else
          # Non-mirrors stay in canceled state (import_data was destroyed)
          log_extra_metadata_on_done(:mirroring_skipped, 'Import was canceled and cannot recover')
          next
        end
      end

      project.import_state.schedule

      unless project.mirror?
        # If the project does not support mirroring (missing license for example)
        # then we mark it as hard failed to exclude from UpdateAllMirrorWorker query
        project.import_state.set_max_retry_count
        project.import_state.mark_as_failed('Project mirroring is not supported')

        log_extra_metadata_on_done(:mirroring_skipped, 'Project does not support mirroring')
      end
    end
  end
end
