# frozen_string_literal: true

module EE
  module ImportHelper
    extend ::Gitlab::Utils::Override

    override :has_ci_cd_only_params?
    def has_ci_cd_only_params?
      params[:ci_cd_only].present?
    end

    override :import_will_timeout_message
    def import_will_timeout_message(ci_cd_only)
      if ci_cd_only
        timeout = time_interval_in_words(::Gitlab.config.gitlab_shell.git_timeout)
        format(_('The connection will time out after %{timeout}. For repositories that take longer, use a clone/push combination.'), timeout: timeout)
      else
        super
      end
    end

    override :import_svn_message
    def import_svn_message(ci_cd_only)
      if ci_cd_only
        svn_link = link_to _('this document'), help_page_path('user/import/_index.md', anchor: 'migrate-from-subversion')
        safe_format(_('To connect an SVN repository, check out %{svn_link}.'), svn_link: svn_link)
      else
        super
      end
    end

    override :import_in_progress_title
    def import_in_progress_title
      if has_ci_cd_only_params?
        _('Connecting…')
      else
        super
      end
    end

    override :import_wait_and_refresh_message
    def import_wait_and_refresh_message
      if has_ci_cd_only_params?
        _('Please wait while we connect to your repository. Refresh at will.')
      else
        super
      end
    end

    override :import_github_title
    def import_github_title
      if has_ci_cd_only_params?
        _('Connect repositories from GitHub')
      else
        super
      end
    end

    override :import_github_authorize_message
    def import_github_authorize_message
      if has_ci_cd_only_params?
        s_('GithubImport|To connect to GitHub repositories, you must first authorize GitLab to access your GitHub repositories.')
      else
        super
      end
    end

    override :import_githubish_choose_repository_message
    def import_githubish_choose_repository_message
      if has_ci_cd_only_params?
        _('Choose which repositories you want to connect and run CI/CD pipelines.')
      else
        super
      end
    end

    override :import_all_githubish_repositories_button_label
    def import_all_githubish_repositories_button_label
      if has_ci_cd_only_params?
        _('Connect all repositories')
      else
        super
      end
    end
  end
end
