# frozen_string_literal: true

module EE
  module CommitsHelper
    extend ::Gitlab::Utils::Override

    override :commit_list_app_data
    def commit_list_app_data
      data = super
      project = @project # rubocop:disable Rails/HelperInstanceVariable -- the CE method this extends reads @project
      return data unless show_pull_mirror_status?(project)

      data.merge('pull_mirror' => ::Gitlab::Json.dump(pull_mirror_data(project)))
    end

    private

    def show_pull_mirror_status?(project)
      project.mirror? && project.import_state.present? && can?(current_user, :push_code, project)
    end

    def pull_mirror_data(project)
      import_state = project.import_state

      {
        url: project.safe_import_url,
        update_status: project.repository_read_only? ? :read_only : import_state.last_update_status,
        last_update_at: import_state.last_update_at&.iso8601,
        last_successful_update_at: import_state.last_successful_update_at&.iso8601,
        ever_updated_successfully: project.mirror_ever_updated_successfully?,
        hard_failed: project.mirror_hard_failed?,
        update_scheduled: import_state.mirror_update_due?,
        updating: import_state.updating_mirror?,
        can_update: can?(current_user, :create_pull_mirror, project),
        settings_path: project_mirror_path(project)
      }
    end
  end
end
