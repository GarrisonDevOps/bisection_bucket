# frozen_string_literal: true

module Integrations
  class GitGuardian < Integration
    validates :token, presence: true, if: :activated?
    validates :api_url, public_url: { schemes: %w[https], allow_blank: true }, if: :activated?

    field :api_url,
      exposes_secrets: true,
      title: -> { s_('GitGuardian|API endpoint') },
      help: -> {
        format(s_(
          'GitGuardian|GitGuardian API base URL. Defaults to %{default_url}. ' \
            'Use %{eu_url} for the EU region, or the URL of your self-hosted GitGuardian instance. Must use HTTPS.'
        ), default_url: Gitlab::GitGuardian::Client::DEFAULT_API_URL, eu_url: 'https://api.eu1.gitguardian.com')
      },
      placeholder: Gitlab::GitGuardian::Client::DEFAULT_API_URL

    field :token,
      type: :password,
      title: 'API token',
      help: -> { s_('GitGuardian|Personal access token to authenticate calls to the GitGuardian API.') },
      non_empty_password_title: -> { s_('ProjectService|Enter new API token') },
      non_empty_password_help: -> { s_('ProjectService|Leave blank to use your current API token.') },
      placeholder: 'Fc6d9dcf3Ab...',
      required: true

    def self.title
      'GitGuardian'
    end

    def self.description
      s_('GitGuardian|Scan pushed commits for hardcoded secrets with GitGuardian, and block pushes that contain them.')
    end

    def self.help
      docs_link = ActionController::Base.helpers.link_to(
        _('Learn more.'),
        Rails.application.routes.url_helpers.help_page_url('user/project/integrations/git_guardian.md'),
        target: '_blank',
        rel: 'noopener noreferrer'
      )

      safe_format(_('Scan pushed commits for hardcoded secrets with GitGuardian, and block pushes that contain them. %{docs_link}'), docs_link: docs_link.html_safe) # rubocop:disable Rails/OutputSafety -- It is fine to call html_safe here
    end

    def self.to_param
      'git_guardian'
    end

    def self.supported_events
      []
    end

    def avatar_url
      ActionController::Base.helpers.image_path(
        'illustrations/third-party-logos/integrations-logos/gitguardian.svg'
      )
    end

    def execute(blobs, repository_url)
      return unless activated?

      ::Gitlab::GitGuardian::Client.new(token, api_url: api_url).execute(blobs, repository_url)
    end

    def testable?
      false
    end
  end
end
