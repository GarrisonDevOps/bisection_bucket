# frozen_string_literal: true

# Use for authentication only, in particular for Rack::Attack.
# Does not perform authorization of scopes, etc.
module Gitlab
  module Auth
    class RequestAuthenticator
      include AuthFinders

      attr_reader :request

      def initialize(request)
        @request = request
      end

      def find_authenticated_requester(request_formats)
        deploy_token_from_request || dependency_proxy_deploy_token || user(request_formats)
      end

      def user(request_formats)
        request_formats.each do |format|
          user = find_sessionless_user(format)

          return user if user
        end

        # Only clear auth-failure context when warden session auth succeeds after
        # a failed token probe. For genuine 401s (bad/expired token, no session)
        # the context is preserved so the failure is logged. For successful
        # token-based sessionless auth, validate_and_save_access_token! already
        # calls clear_auth_failure_in_application_context on success, so no
        # explicit reset is needed there.
        warden_user = find_user_from_warden
        clear_auth_failure_in_application_context(true) if warden_user
        warden_user
      end

      def runner
        find_runner_from_token
      rescue Gitlab::Auth::AuthenticationError
        nil
      end

      def job_from_token
        find_job_from_job_token
      rescue Gitlab::Auth::AuthenticationError
        nil
      end

      def find_sessionless_user(request_format)
        case request_format
        when :graphql_api
          find_user_for_graphql_api_request
        when :api, :git, :rss, :ics, :blob, :download, :archive, nil
          find_user_from_any_authentication_method(request_format)
        when :design
          # Deliberately narrower than find_user_from_any_authentication_method:
          # design images must only ever accept PAT/OAuth tokens with api or
          # read_api scope, never feed, static object, or CI job tokens.
          # Tokens must arrive in a header (PRIVATE-TOKEN or Authorization:
          # Bearer): query string tokens leak into logs and browser history.
          # Requests carrying one fail closed rather than falling back to a
          # header, because extract_personal_access_token prefers the query
          # parameter over the header.
          find_user_from_web_access_token(:design, scopes: [:api, :read_api]) unless token_in_query_string?
        when :editor_extension, :oauth_token_check
          find_user_from_access_token
        else
          raise ArgumentError, "Unknown request format"
        end
      rescue Gitlab::Auth::AuthenticationError
        nil
      end

      def can_sign_in_bot?(user)
        return false if user&.blocked?

        # Allow bots and service accounts to access both API and archive endpoints
        (user&.project_bot? || user&.service_account?) && (api_request? || archive_request?)
      end

      def valid_access_token?(scopes: [])
        # We may just be checking whether the user has :admin_mode access, so
        # don't construe an auth failure as a real failure.
        validate_and_save_access_token!(scopes: scopes, save_auth_context: false)

        true
      rescue Gitlab::Auth::AuthenticationError
        false
      end

      def current_token_scopes
        access_token&.scopes.to_a
      end

      def granular_access_token?
        access_token&.try(:granular?) || false
      end

      private

      def dependency_proxy_deploy_token
        user_or_deploy_token = dependency_proxy_requester
        user_or_deploy_token if user_or_deploy_token.is_a?(::DeployToken)
      end

      # Use a minimal subset of find_user_from_any_authentication_method
      # so only token types allowed for GraphQL can authenticate users.
      # CI_JOB_TOKENs are not allowed for now, since their access is too broad.
      #
      # Overridden in EE
      def find_user_for_graphql_api_request
        find_user_from_web_access_token(:api, scopes: graphql_authorization_scopes) ||
          find_user_from_personal_access_token_for_api_or_git
      end

      # Overridden in EE
      def graphql_authorization_scopes
        [:api, :read_api]
      end

      def find_user_from_any_authentication_method(request_format)
        find_user_from_dependency_proxy_token ||
          find_user_from_job_bearer_token ||
          find_user_from_web_access_token(request_format, scopes: [:api, :read_api]) ||
          find_user_from_feed_token(request_format) ||
          find_user_from_static_object_token(request_format) ||
          find_user_from_job_token ||
          find_user_from_personal_access_token_for_api_or_git ||
          find_user_for_git_or_lfs_request
      end

      # Every query parameter the token finders would read: private_token
      # for PATs (extract_personal_access_token), access_token and
      # bearer_token for OAuth (Doorkeeper#access_token_methods).
      def token_in_query_string?
        [PRIVATE_TOKEN_PARAM.to_s, 'access_token', 'bearer_token'].any? do |key|
          current_request.query_parameters[key].present?
        end
      end

      def access_token
        strong_memoize(:access_token) do
          super || find_personal_access_token_from_http_basic_auth
        end
      end

      # The throttles also count info/refs without .git, which the router redirects to the repository.
      def git_request?
        super || git_http_request?
      end

      # Anchored, unlike git_request?, which also matches web paths such as /-/archive/main/x.git.zip.
      def git_http_request?
        Gitlab::PathRegex.repository_git_http_route_regex.match?(logical_path)
      end

      def logical_path
        current_request.path.delete_prefix(Gitlab.config.gitlab.relative_url_root)
      end

      # Skip non-job-token passwords so a PAT sent as gitlab-ci-token:<PAT> is still rate limited as its user.
      # Memoized so the formats #user tries share one lookup, also when the job isn't running and super raises.
      def find_user_from_job_token_basic_auth
        return unless has_basic_credentials?(current_request)

        _, password = user_name_and_password(current_request)
        return unless ::Authn::Tokens::CiJobToken.prefix?(password.to_s)

        result = strong_memoize(:job_token_basic_auth_result) do
          super
        rescue Gitlab::Auth::AuthenticationError => e
          e
        end

        raise result if result.is_a?(Gitlab::Auth::AuthenticationError)

        result
      end

      # The base finder reads Bearer job tokens wherever job tokens are allowed, but Git paths take basic auth only.
      def find_user_from_job_bearer_token
        super if api_request?
      end

      def job_token_allowed
        return %i[request basic_auth] if api_request?
        return false unless git_http_request?
        # Object transfers stay per IP until their per-user limit is sized: https://gitlab.com/gitlab-org/gitlab/-/work_items/634586
        return false if lfs_object_request?
        # repository_git_http_route_regex is shared with the throttles and also matches a bare /<repo>.git,
        # which is the project or group page and signs in sessionless users before redirecting.
        return false if current_request.path.end_with?('.git')

        # The Git and LFS controllers read job tokens from basic auth only.
        %i[basic_auth]
      end

      def lfs_object_request?
        Gitlab::PathRegex.repository_git_lfs_object_route_regex.match?(logical_path)
      end

      def route_authentication_setting
        @route_authentication_setting ||= {
          job_token_allowed: job_token_allowed,
          basic_auth_personal_access_token: api_request? || git_request?,
          deploy_token_allowed: api_request? || git_request?
        }
      end
    end
  end
end

Gitlab::Auth::RequestAuthenticator.prepend_mod
