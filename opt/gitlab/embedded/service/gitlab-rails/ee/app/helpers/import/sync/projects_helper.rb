# frozen_string_literal: true

module Import
  module Sync
    module ProjectsHelper
      def github_updates_repository_url(import_sync_repository)
        full_name = import_sync_repository.provider_full_name
        return unless ::Import::Sync::Repositories::Authentication.valid_full_name?(full_name)

        base_url = ::Import::Sync::Repositories::Authentication.for(import_sync_repository).web_base_url
        "#{base_url}/#{full_name.split('/').map { |segment| ERB::Util.url_encode(segment) }.join('/')}"
      rescue URI::InvalidURIError
        # The panel holds the only way to stop updates, so a bad import URL must not break it.
        nil
      end

      def github_updates_settings_data(project, import_sync_repository)
        {
          status_url: status_project_github_updates_path(project),
          update_now_url:
            can?(current_user, :update_github_update, project) ? update_now_project_github_updates_path(project) : '',
          stop_url: can?(current_user, :stop_github_update, project) ? stop_project_github_updates_path(project) : '',
          project_full_path: project.full_path,
          repository_name: import_sync_repository.provider_full_name,
          repository_url: github_updates_repository_url(import_sync_repository).to_s,
          initial_status: Gitlab::Json.dump(
            ::Import::Sync::GithubUpdatesStatusPresenter.new(import_sync_repository).to_h
          )
        }
      end

      # rubocop:disable Layout/LineLength -- Keep each localized sentence extractable as one literal.
      # The connection state can be private, so users who can't read the status get the generic sentence.
      def github_updates_read_only_notice_body(project)
        import_sync_repository = project.import_sync_repository
        return unless import_sync_repository

        authority_state = import_sync_repository.authority_state if can?(current_user, :read_github_update, project)

        case authority_state
        when 'provisioning'
          s_('GithubUpdatesReadOnly|GitLab is setting up updates from GitHub. This project stays read-only until the setup finishes.')
        when 'disconnected'
          s_('GithubUpdatesReadOnly|GitLab lost its connection to GitHub. This project stays read-only until GitLab can check GitHub for the latest changes.')
        when 'cutting_over'
          s_('GithubUpdatesReadOnly|GitHub updates are stopping. This project stays read-only until GitLab finishes a final check of GitHub.')
        when 'cutover_failed'
          s_("GithubUpdatesReadOnly|GitLab couldn't stop GitHub updates. This project stays read-only until updates stop.")
        else
          s_('GithubUpdatesReadOnly|Updates from GitHub are on for this project. Make changes in GitHub.')
        end
      end
      # rubocop:enable Layout/LineLength

      # A setup canceled before syncing started leaves a row behind with nothing to show.
      def show_github_updates_settings?(import_sync_repository)
        import_sync_repository.present? && !import_sync_repository.bootstrap_canceled?
      end

      def show_github_updates_notice?(project)
        ::Import::Sync::Projects::WritePolicy.read_only?(project)
      end
    end
  end
end
