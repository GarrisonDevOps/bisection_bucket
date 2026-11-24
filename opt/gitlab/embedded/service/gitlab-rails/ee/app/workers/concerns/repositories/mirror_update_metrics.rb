# frozen_string_literal: true

module Repositories
  module MirrorUpdateMetrics
    extend ActiveSupport::Concern

    def log_mirror_update_finished(project, async_branch_creation: false)
      import_state = project.import_state

      Gitlab::AppLogger.info(
        message: "Mirror update for #{project.full_path} successfully finished. " \
          "Update duration: #{import_state.mirror_update_duration}",
        async_branch_creation: async_branch_creation,
        jid: jid
      )

      metric_mirror_update_duration_seconds.observe({}, import_state.mirror_update_duration)
    end

    private

    def metric_mirror_update_duration_seconds
      @metric_mirror_update_duration_seconds ||= Gitlab::Metrics.histogram(
        :gitlab_repository_mirror_update_duration_seconds,
        'Mirror update duration',
        {},
        [0.1, 1.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
      )
    end
  end
end
