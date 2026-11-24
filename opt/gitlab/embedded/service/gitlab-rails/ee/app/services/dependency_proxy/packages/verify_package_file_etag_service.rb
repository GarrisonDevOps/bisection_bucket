# frozen_string_literal: true

module DependencyProxy
  module Packages
    class VerifyPackageFileEtagService
      include ::Gitlab::Utils::StrongMemoize

      REGISTRY_NOT_AVAILABLE_ERROR_CODE = 503
      REGISTRY_NOT_AVAILABLE_MESSAGE = 'External registry is not available'
      TIMEOUT = 5

      def initialize(remote_url:, package_file:, headers: {})
        @remote_url = remote_url
        @package_file = package_file
        @headers = headers
      end

      def execute
        return ServiceResponse.error(message: 'invalid arguments', reason: :invalid_arguments) unless valid?
        return error_with_response_code unless response.success?
        return ServiceResponse.error(message: 'no etag from external registry', reason: :no_etag) if etag.blank?
        return ServiceResponse.success if etag_match?

        ServiceResponse.error(
          message: "etag from external registry doesn't match any known digests",
          reason: :wrong_etag
        )
      rescue *::Gitlab::HTTP::HTTP_ERRORS
        error_with_response_code(
          code: REGISTRY_NOT_AVAILABLE_ERROR_CODE,
          message: REGISTRY_NOT_AVAILABLE_MESSAGE
        )
      end

      private

      attr_reader :remote_url, :package_file, :headers

      def response
        ::Gitlab::HTTP.head(remote_url, headers: headers, follow_redirects: true, timeout: TIMEOUT)
      end
      strong_memoize_attr :response

      def etag_match?
        return false unless sanitized_etag

        # Remote registries can have different ways to return the ETag field:
        # GitLab: md5
        # Maven Central: md5
        # Artifactory: sha1
        # Github: No ETag field
        # Sonatype Nexus: custom string with the sha1. Example {SHA1{e9702caacd0b915b0495f6d191371d61c379cd1c}}.
        #
        # We thus need to check the etag field in different ways.

        return true if %i[md5 sha1 sha256].any? { |digest| sanitized_etag == package_file["file_#{digest}"] }
        return true if %i[sha1].any? { |digest| sanitized_etag.include?(package_file["file_#{digest}"]) }

        false
      end

      def sanitized_etag
        return unless etag.present?

        etag.delete('"')
      end
      strong_memoize_attr :sanitized_etag

      def etag
        response.headers['etag']
      end
      strong_memoize_attr :etag

      def valid?
        remote_url.present? && package_file
      end

      def error_with_response_code(code: response.code, message: nil)
        message ||= "Received #{code} from external registry"
        Gitlab::AppLogger.error(
          service_class: self.class.to_s,
          project_id: package_file.project_id,
          message: message
        )

        ServiceResponse.error(message: message, reason: :response_error_code)
      end
    end
  end
end
