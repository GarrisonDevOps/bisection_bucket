# frozen_string_literal: true

module VirtualRegistries
  module Container
    class HandleReferrersRequestService < ::VirtualRegistries::BaseService
      EMPTY_INDEX = {
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.index.v1+json',
        manifests: []
      }.freeze

      MAX_RESPONSE_SIZE = 1.megabyte
      ARTIFACT_TYPE_MAX_LENGTH = 255
      # Conservative media-type format: type/subtype (no parameters)
      ARTIFACT_TYPE_FORMAT_REGEX = %r{\A[a-zA-Z0-9][\w.\-]*/[a-zA-Z0-9][\w.\-+]*\z}

      ERRORS = BASE_ERRORS.merge(
        unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
        no_upstreams: ServiceResponse.error(message: 'No upstreams set', reason: :no_upstreams),
        upstream_not_available: ServiceResponse.error(
          message: 'Upstream not available',
          reason: :upstream_not_available
        ),
        upstream_auth_error: ServiceResponse.error(
          message: 'Upstream authorization failed',
          reason: :upstream_auth_error
        ),
        invalid_artifact_type: ServiceResponse.error(
          message: 'Invalid artifactType parameter',
          reason: :invalid_artifact_type
        )
      ).freeze

      def execute
        return ERRORS[:path_not_present] unless path.present?
        return ERRORS[:unauthorized] unless allowed?
        return ERRORS[:no_upstreams] if registry.upstreams.empty?
        return ERRORS[:invalid_artifact_type] if artifact_type_invalid?

        upstream = registry.upstreams.first
        response = fetch_from_upstream(upstream)

        build_service_response(response)
      rescue *::Gitlab::HTTP::HTTP_ERRORS
        ERRORS[:upstream_not_available]
      end

      private

      def allowed?
        return false unless current_user

        can?(current_user, :read_virtual_registry, registry)
      end

      def path
        params[:path]
      end

      def artifact_type
        params[:artifact_type]
      end

      def artifact_type_invalid?
        return false if artifact_type.blank?

        artifact_type.length > ARTIFACT_TYPE_MAX_LENGTH ||
          !ARTIFACT_TYPE_FORMAT_REGEX.match?(artifact_type)
      end

      def fetch_from_upstream(upstream)
        url = upstream.url_for(path)
        url = append_artifact_type(url)

        ::Gitlab::HTTP.get(
          url,
          headers: upstream.headers(path),
          follow_redirects: true,
          timeout: NETWORK_TIMEOUT,
          max_bytes: MAX_RESPONSE_SIZE
        )
      end

      def append_artifact_type(url)
        return url if artifact_type.blank?

        uri = Addressable::URI.parse(url)
        query_values = uri.query_values || {}
        uri.query_values = query_values.merge(artifactType: artifact_type)
        uri.to_s
      end

      def build_service_response(response)
        if response.success?
          ServiceResponse.success(
            payload: {
              raw_body: response.body,
              filters_applied: response.headers['OCI-Filters-Applied']
            }
          )
        elsif response.not_found?
          ServiceResponse.success(
            payload: {
              raw_body: EMPTY_INDEX.to_json,
              filters_applied: nil
            }
          )
        elsif response.unauthorized? || response.forbidden?
          ERRORS[:upstream_auth_error]
        else
          ERRORS[:upstream_not_available]
        end
      end
    end
  end
end
