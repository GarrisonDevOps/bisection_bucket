# frozen_string_literal: true

module VirtualRegistries
  class ContainerController < ::ApplicationController
    include ::JwtAuthenticatable
    include WorkhorseRequest
    include SendFileUpload
    include ::PackagesHelper
    include Gitlab::Utils::StrongMemoize

    PERMITTED_PARAMS = %i[id file path artifactType image].freeze

    EXTRA_RESPONSE_HEADERS = {
      'Docker-Distribution-Api-Version' => 'registry/2.0',
      'Content-Security-Policy' => "sandbox; default-src 'none'; require-trusted-types-for 'script'",
      'X-Content-Type-Options' => 'nosniff'
    }.freeze

    OCI_REFERRERS_CONTENT_TYPE = 'application/vnd.oci.image.index.v1+json'
    VALID_OCI_IMAGE_REGEX = /\A#{::Gitlab::PathRegex.container_image_regex.source}\z/o

    ALLOWED_RESPONSE_HEADERS = %w[
      Content-Length
      Content-Type
      Docker-Content-Digest
      Docker-Distribution-Api-Version
      Etag
    ].freeze

    UPSTREAM_GID_HEADER = 'X-Gitlab-Virtual-Registry-Upstream-Global-Id'
    MAX_FILE_SIZE = 5.gigabytes

    delegate :actor, to: :@authentication_result, allow_nil: true
    alias_method :authenticated_user, :actor

    # We disable `authenticate_user!` since we perform auth using JWT token
    skip_before_action :authenticate_user!, raise: false

    before_action :verify_workhorse_api!, only: [:upload]
    skip_before_action :verify_authenticity_token, only: [:upload]

    before_action :skip_session
    before_action :ensure_feature_available!
    before_action :authenticate_user_from_jwt_token!
    before_action :ensure_user_has_access!
    before_action :check_rate_limit_for_virtual_registry!

    skip_before_action(
      :ensure_feature_available!,
      :authenticate_user_from_jwt_token!,
      :ensure_user_has_access!,
      only: [:referrers_not_found]
    )

    feature_category :virtual_registry
    urgency :low

    def show
      service_response = ::VirtualRegistries::Container::HandleFileRequestService.new(
        registry: registry,
        current_user: authenticated_user,
        params: { path: path }
      ).execute

      if service_response.error?
        send_error_response_from!(service_response: service_response)
      else
        send_successful_response_from(service_response: service_response)
      end
    end

    def upload
      return render_404 unless registry.upstreams.include?(upstream_from_header)

      service_response = ::VirtualRegistries::Container::Cache::Entries::CreateOrUpdateService.new(
        upstream: upstream_from_header,
        current_user: authenticated_user,
        params: upload_params
      ).execute

      if service_response.error?
        send_error_response_from!(service_response: service_response)
      else
        head :ok
      end
    end

    def referrers
      service_response = ::VirtualRegistries::Container::HandleReferrersRequestService.new(
        registry: registry,
        current_user: authenticated_user,
        params: { path: path, artifact_type: permitted_params[:artifactType] }
      ).execute

      if service_response.error?
        send_error_response_from!(service_response: service_response)
      else
        payload = service_response.payload
        response.headers['OCI-Filters-Applied'] = payload[:filters_applied] if payload[:filters_applied].present?
        render body: payload[:raw_body], status: :ok, content_type: OCI_REFERRERS_CONTENT_TYPE
      end
    end

    def referrers_not_found
      response.headers['Docker-Distribution-Api-Version'] = EXTRA_RESPONSE_HEADERS['Docker-Distribution-Api-Version']

      image = permitted_params[:image]
      error = if !VALID_OCI_IMAGE_REGEX.match?(image)
                { code: 'NAME_INVALID', message: 'Invalid repository name' }
              else
                { code: 'DIGEST_INVALID', message: 'Invalid digest format' }
              end

      render status: :bad_request, json: { errors: [error] }
    end

    private

    def ensure_feature_available!
      render_404 unless registry && ::VirtualRegistries::Container.feature_enabled?(registry.group)
    end

    def registry
      ::VirtualRegistries::Container::Registry.find_by_id(permitted_params[:id])
    end
    strong_memoize_attr :registry

    def permitted_params
      params.permit(PERMITTED_PARAMS)
    end

    def ensure_user_has_access!
      render_404 unless ::VirtualRegistries.user_has_access?(registry.group, authenticated_user)
    end

    def valid_service_type?(service_type)
      service_type == ::Auth::ContainerProxyAuthenticationService::SERVICE_TYPE_VIRTUAL_REGISTRY
    end

    def check_rate_limit_for_virtual_registry!
      check_rate_limit!(:virtual_registries_endpoints_api_limit, scope: { ip: request.ip, group: registry&.group })
    end

    def path
      permitted_params[:path]
    end

    def send_successful_response_from(service_response:)
      action, action_params = service_response.to_h.values_at(:action, :action_params)

      case action
      when :download_file
        send_cached_file(action_params)
      when :workhorse_upload_url
        workhorse_upload_url(**action_params.slice(:url, :upstream, :overwrite))
      end
    end

    def send_cached_file(action_params)
      file = action_params[:file]
      content_type = action_params[:content_type]
      digest = action_params[:digest].presence || action_params[:upstream_etag]

      extra_headers = EXTRA_RESPONSE_HEADERS.dup
      extra_headers['Content-Type'] = content_type if content_type.present?
      extra_headers['Docker-Content-Digest'] = digest if manifest_request? && digest.present?
      extra_headers.each { |key, value| response.headers[key] = value }

      # Sending the file on HEAD yields Content-Length: 0, which containerd rejects.
      if request.head? && action_params[:size].present?
        response.headers['Content-Length'] = action_params[:size].to_s
        return head :ok
      end

      send_upload(
        file,
        redirect_params: { query: { 'response-content-type' => content_type } },
        send_params: { type: content_type },
        ssrf_params: {
          restrict_forwarded_response_headers: {
            enabled: true,
            allow_list: ALLOWED_RESPONSE_HEADERS
          }
        }
      )
    end

    def workhorse_upload_url(url:, upstream:, overwrite: false)
      # Reached from the #show (pull) action, whose before_action only verifies
      # the Workhorse JWT for :upload. This senddata payload carries the upstream
      # registry's Basic-auth credentials, so gate the emit itself (via the
      # SendFileUpload helper) rather than relying on the action-level guard.
      store_workhorse_send_data! do
        Gitlab::Workhorse.send_dependency(
          upstream.headers(path),
          url,
          response_headers: EXTRA_RESPONSE_HEADERS,
          allow_localhost: allow_localhost?,
          allowed_endpoints: allowed_endpoints,
          ssrf_filter: true,
          upload_config: {
            headers: { UPSTREAM_GID_HEADER => upstream.to_global_id.to_s },
            authorized_upload_response: authorized_upload_response(upstream, overwrite:)
          },
          restrict_forwarded_response_headers: {
            enabled: true,
            allow_list: ALLOWED_RESPONSE_HEADERS
          }
        )
      end

      response.content_type = 'application/octet-stream'
      EXTRA_RESPONSE_HEADERS.each { |key, value| response.headers[key] = value }

      head :ok
    end

    # object_storage_key is read-only, so a refetch uploads to a temp path.
    # The cache entry service then copies it onto the entry's existing key.
    def authorized_upload_response(upstream, overwrite:)
      final_store_path_options =
        if overwrite
          {}
        else
          { use_final_store_path: true, final_store_path_config: { override_path: upstream.object_storage_key } }
        end

      ::VirtualRegistries::Cache::EntryUploader.workhorse_authorize(
        has_length: true,
        maximum_size: MAX_FILE_SIZE,
        **final_store_path_options
      )
    end

    def allow_localhost?
      Gitlab.dev_or_test_env? || Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?
    end

    def allowed_endpoints
      # rubocop:disable Naming/InclusiveLanguage -- existing setting
      ObjectStoreSettings.enabled_endpoint_uris + Gitlab::CurrentSettings.outbound_local_requests_whitelist
      # rubocop:enable Naming/InclusiveLanguage
    end

    def manifest_request?
      path.include?('/manifests/')
    end

    def send_error_response_from!(service_response:)
      case service_response.reason
      when :unauthorized
        access_denied!(service_response.message)
      when :no_upstreams, :file_not_found_on_upstreams
        render_404
      when :upstream_not_available, :cache_entry_removed
        render_503(service_response.message)
      when :upstream_auth_error
        render json: { message: service_response.message }, status: :bad_gateway
      when :invalid_artifact_type
        render status: :bad_request, json: { errors: [{ code: 'UNSUPPORTED', message: service_response.message }] }
      else
        render json: { message: 'Bad Request' }, status: :bad_request
      end
    end

    def upstream_from_header
      upstream_gid = request.headers[UPSTREAM_GID_HEADER]
      Gitlab::GlobalId.safe_locate(upstream_gid, options: { only: ::VirtualRegistries::Container::Upstream })
    end
    strong_memoize_attr :upstream_from_header

    def upload_params
      {
        path: path,
        file: permitted_params[:file],
        etag: ::VirtualRegistries::Container.sanitize_etag(request.headers['Etag']),
        content_type: request.headers[Gitlab::Workhorse::SEND_DEPENDENCY_CONTENT_TYPE_HEADER]
      }
    end
  end
end
