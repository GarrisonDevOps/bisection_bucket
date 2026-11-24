# frozen_string_literal: true

module Repositories
  class GitHttpController < ::Repositories::GitHttpClientController
    include Gitlab::Identifier
    include WorkhorseRequest

    SSH_ACTIONS = %w[ssh_upload_pack ssh_receive_pack].freeze

    before_action :ensure_ssh_git_http_authenticated, if: :ssh_over_http_request?
    before_action :access_check
    before_action :check_push_rate_limit, only: :git_receive_pack
    prepend_before_action :deny_head_requests, only: [:info_refs]

    rescue_from Gitlab::GitAccess::ForbiddenError, with: :render_403_with_exception
    rescue_from JWT::DecodeError, with: :render_403_with_exception
    rescue_from Gitlab::GitAccess::NotFoundError, with: :render_404_with_exception
    rescue_from Gitlab::GitAccessProject::CreationError, with: :render_422_with_exception
    rescue_from Gitlab::GitAccess::TimeoutError, with: :render_503_with_exception
    rescue_from GRPC::Unavailable do |e|
      render_503_with_exception(
        e,
        message: 'The git server, Gitaly, is not available at this time. Please contact your administrator.'
      )
    end

    # GET /foo/bar.git/info/refs?service=git-upload-pack (git pull)
    # GET /foo/bar.git/info/refs?service=git-receive-pack (git push)
    def info_refs
      log_user_activity if upload_pack?

      render_ok
    end

    # POST /foo/bar.git/git-upload-pack (git pull)
    def git_upload_pack
      update_fetch_statistics

      render_ok
    end

    # POST /foo/bar.git/git-receive-pack" (git push)
    def git_receive_pack
      render_ok
    end

    # POST /foo/bar.git/ssh-upload-pack" (git pull via SSH)
    def ssh_upload_pack
      render_ssh_git_http_ok(:git_upload_pack)
    end

    # POST /foo/bar.git/ssh-receive-pack" (git push via SSH)
    def ssh_receive_pack
      render_ssh_git_http_ok(:git_receive_pack)
    end

    private

    attr_reader :shell_deploy_key

    def deny_head_requests
      head :forbidden if request.head?
    end

    def authenticate_user
      return super unless ssh_over_http_request?

      @authentication_result = Gitlab::Auth::Result::EMPTY
      handle_shell_authentication
    end

    def ssh_over_http_request?
      action_name.in?(SSH_ACTIONS)
    end

    def shell_request?
      authentication_result.gitlab_shell?
    end

    def shell_api_request?
      ::Gitlab::Shell.header_set?(request.headers)
    end

    def handle_shell_authentication
      return unless shell_api_payload

      user = identify(shell_api_payload['gl_id'])
      return unless user.is_a?(User)

      if shell_api_claims
        result = shell_api_claims.verify(user)
        return log_rejected_shell_claims(result) if result.error?

        @shell_deploy_key = result.payload[:deploy_key]
      end

      @authentication_result = ::Gitlab::Auth::Result.new(
        user, project, :gitlab_shell,
        ::Gitlab::Auth.read_write_project_authentication_abilities
      )
    end

    def shell_api_payload
      return unless ssh_over_http_request? && shell_api_request?

      payload, = ::Gitlab::Shell.verify_api_request(request.headers)
      payload
    end
    strong_memoize_attr :shell_api_payload

    def shell_api_claims
      return unless shell_api_payload
      return unless Feature.enabled?(:cells_shell_jwt_key_claims, :instance)

      ::Gitlab::Shell::ApiRequestClaims.new(shell_api_payload)
    end
    strong_memoize_attr :shell_api_claims

    def shell_client_ip
      shell_api_claims&.client_ip
    end
    strong_memoize_attr :shell_client_ip

    def log_rejected_shell_claims(result)
      ::Gitlab::AuthLogger.warn(
        Labkit::Fields::LOG_MESSAGE => result.message,
        Labkit::Fields::ADDITIONAL_DETAILS => "#{result.reason}, gl_key_id: #{result.payload[:gl_key_id].inspect}",
        Labkit::Fields::GL_PROJECT_PATH => project&.full_path
      )
    end

    # gitlab-shell sends the SSH client IP it passed to /allowed, because request.ip is
    # gitlab-shell's egress address. It must be set before authentication, as policies are cached.
    def set_current_ip_address(&block)
      return super unless shell_client_ip

      ::Gitlab::IpAddressState.with(shell_client_ip, &block) # rubocop: disable CodeReuse/ActiveRecord -- not an ActiveRecord model
    end

    def set_current_context
      super do
        ::Gitlab::ApplicationContext.push(remote_ip: shell_client_ip) if shell_client_ip
        yield
      end
    end

    # SSH-over-HTTP endpoints require a recognized authentication result. If the
    # request was not authenticated for these endpoints, respond with 404 so they
    # are indistinguishable from a non-existent route and never advertise
    # repository existence. In CE only Shell JWT auth is accepted; EE extends this
    # to also accept Geo-authenticated requests.
    def ensure_ssh_git_http_authenticated
      render_not_found unless ssh_git_http_authenticated?
    end

    def ssh_git_http_authenticated?
      shell_request?
    end

    def need_git_audit_event?
      false
    end

    def render_ssh_git_http_ok(command)
      set_workhorse_internal_api_content_type
      payload = Gitlab::Workhorse.git_http_ok(repository, repo_type, user, command,
        show_all_refs: false, need_audit: need_git_audit_event?)
      # Match direct SSH: gitlab-shell sends GL_ID key-<id> so Gitaly hooks authorize the
      # deploy key, but keeps the owner as user_id in Gitaly call metadata.
      payload[:GL_ID] = shell_deploy_key.shell_id if shell_deploy_key
      render json: payload
    end

    def render_not_found
      render plain: "Not found", status: :not_found
    end

    def download_request?
      upload_pack?
    end

    def upload_pack?
      git_command == 'git-upload-pack'
    end

    def git_command
      case action_name
      when 'info_refs'
        params.permit(:service)[:service]
      when 'ssh_upload_pack'
        'git-upload-pack'
      when 'ssh_receive_pack'
        'git-receive-pack'
      else
        action_name.dasherize
      end
    end

    def render_ok
      set_workhorse_internal_api_content_type

      params = { authentication_context: authentication_result.authentication_context }
      yield(params) if block_given?

      render json: Gitlab::Workhorse.git_http_ok(repository, repo_type, user, action_name, **params)
    end

    def render_403_with_exception(exception)
      render plain: exception.message, status: :forbidden
    end

    def render_404_with_exception(exception)
      render plain: exception.message, status: :not_found
    end

    def render_422_with_exception(exception)
      render plain: exception.message, status: :unprocessable_entity
    end

    def render_503_with_exception(exception, message: nil)
      render plain: message || exception.message, status: :service_unavailable
    end

    def check_push_rate_limit
      render_push_rate_limited if push_rate_limited?
    end

    def push_rate_limited?
      repo_type.project? &&
        Gitlab::Repositories::PushRateLimit.throttled?(request: request, user: user, project: project)
    end

    def render_push_rate_limited
      response.headers['Retry-After'] = Gitlab::Repositories::PushRateLimit.retry_after.to_s
      response.headers['RateLimit-Name'] = Gitlab::Repositories::PushRateLimit::KEY.to_s
      render plain: Gitlab::Repositories::PushRateLimit::MESSAGE, status: :too_many_requests
    end

    def update_fetch_statistics
      return unless project
      return if Gitlab::Database.read_only?
      return unless repo_type.project?
      return if Feature.enabled?(:disable_git_http_fetch_writes)

      Projects::FetchStatisticsIncrementService.new(project).execute
    end

    def access
      @access ||= access_klass.new(access_actor, container, git_access_protocol,
        authentication_abilities: authentication_abilities,
        repository_path: repository_path,
        redirected_path: redirected_path,
        auth_result_type: auth_result_type,
        personal_access_token: personal_access_token,
        oauth_access_token: oauth_access_token)
    end

    def git_access_protocol
      shell_request? ? 'ssh' : 'http'
    end

    def access_actor
      return shell_deploy_key if shell_deploy_key
      return user if user

      :ci if ci?
    end

    def access_check
      access.check(git_command, Gitlab::GitAccess::ANY)

      @project = @container = access.container if repo_type.project? && !container
    end

    def access_klass
      @access_klass ||= repo_type.access_checker_class
    end

    def log_user_activity
      Users::ActivityService.new(author: user, project: project, namespace: project&.namespace).execute

      return unless project && user

      Gitlab::EventStore.publish(
        Users::ActivityEvent.new(data: {
          user_id: user.id,
          namespace_id: project.root_ancestor.id
        })
      )
    end

    def append_info_to_payload(payload)
      super

      payload[:metadata] ||= {}
      payload[:metadata][:repository_storage] = project&.repository_storage
    end
  end
end

::Repositories::GitHttpController.prepend_mod_with('Repositories::GitHttpController')
