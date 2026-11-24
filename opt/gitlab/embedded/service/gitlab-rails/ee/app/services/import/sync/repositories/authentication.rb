# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Handles GitHub credentials for one synced repository. It builds the API client, a clone URL
      # without credentials, and the auth header Gitaly needs for fetches. The token is read from the
      # project's import data only when needed, and it never ends up in a URL, a log or job arguments.
      class Authentication
        include ::Gitlab::Utils::StrongMemoize

        INVALID_REPOSITORY_PATH_SEGMENTS = %w[. ..].freeze
        REPOSITORY_PATH_SEGMENT = /\A[0-9A-Za-z_.-]+\z/

        def self.for(repository)
          new(repository)
        end

        # The name goes into a clone URL, so only two plain segments are allowed and "." or ".."
        # are rejected, which keeps it from changing the URL path.
        def self.valid_full_name?(full_name)
          segments = full_name.to_s.split('/', -1)
          return false unless segments.size == 2

          segments.all? do |segment|
            segment.match?(REPOSITORY_PATH_SEGMENT) && INVALID_REPOSITORY_PATH_SEGMENTS.exclude?(segment)
          end
        end

        def initialize(repository)
          @repository = repository
        end

        def client(parallel: true)
          ::Gitlab::GithubImport.new_client_for(project, token: token, parallel: parallel)
        end

        # Credential-free clone URL on the same host the API client targets (github.com or GHE).
        def repository_url
          full_name = repository.provider_full_name.to_s
          unless self.class.valid_full_name?(full_name)
            raise Errors::ProviderIdentityError, 'GitHub repository identity is invalid'
          end

          "#{web_base_url}/#{full_name.delete_suffix('.git')}.git"
        end

        # Scheme, host and port of the GitHub instance the project was imported from, without credentials.
        def web_base_url
          url = URI.parse(project.unsafe_import_url.to_s)
          return 'https://github.com' if url.host.blank?

          url.user = url.password = url.query = url.fragment = nil
          url.path = ''
          url.to_s
        end

        # In-memory header for Gitaly fetches, so the URL stays credential-free.
        def http_authorization_header
          "Basic #{Base64.strict_encode64("x-access-token:#{token}")}"
        end

        # Checked on every pass, like a pull mirror, so outbound request settings and DNS changes made after
        # the import still apply. Gitaly then connects to the address that passed the check.
        def resolved_address
          url, resolved_host = ::Gitlab::HTTP_V2::UrlBlocker.validate!(
            repository_url,
            schemes: Project::VALID_IMPORT_PROTOCOLS,
            ports: Project::VALID_IMPORT_PORTS,
            allow_localhost: allow_local_requests?,
            allow_local_network: allow_local_requests?,
            dns_rebind_protection: dns_rebind_protection?,
            deny_all_requests_except_allowed: ::Gitlab::CurrentSettings.deny_all_requests_except_allowed?,
            outbound_local_requests_allowlist: ::Gitlab::CurrentSettings.outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting
          )
          return '' if resolved_host.nil? || !url.scheme.in?(%w[http https])

          url.hostname.to_s
        end
        strong_memoize_attr :resolved_address

        def inspect
          "#<#{self.class.name} repository_id=#{repository.id}>"
        end

        private

        attr_reader :repository

        def project
          repository.project
        end

        def allow_local_requests?
          ::Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?
        end

        def dns_rebind_protection?
          return false if ::Gitlab.http_proxy_env?

          ::Gitlab::CurrentSettings.dns_rebinding_protection_enabled?
        end

        def token
          raise Errors::MissingCredentialsError, 'Project import data is missing' unless project.import_data

          ::Import::Github::RefreshOauthTokenService.new(project).current_token.presence ||
            raise(Errors::MissingCredentialsError, 'GitHub access token is missing')
        end
      end
    end
  end
end
