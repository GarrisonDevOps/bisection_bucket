# frozen_string_literal: true

module ArtifactRegistry
  module RendersErrors
    extend ActiveSupport::Concern

    def render_artifact_registry_response(operation: :query, errors: nil)
      raise ArgumentError, '`errors:` is required when operation is :mutation' if operation == :mutation && errors.nil?

      begin
        yield
      rescue ::ArtifactRegistry::Client::AuthorizationError => e
        render_artifact_registry_authorization_error(e, operation)
      rescue ::ArtifactRegistry::Client::ConfigurationError,
        ::ArtifactRegistry::Client::UnavailableError => e
        raise artifact_registry_service_unavailable_error(e)
      rescue ::ArtifactRegistry::Client::ApiError => e
        render_artifact_registry_api_error(e, operation, errors)
      rescue ::ArgumentError => e
        raise ::Gitlab::Graphql::Errors::ArgumentError, e.message
      end
    end

    private

    def render_artifact_registry_authorization_error(error, operation)
      if error.status.nil?
        ::Gitlab::ErrorTracking.log_exception(error)

        raise artifact_registry_service_unavailable_error(error)
      end

      raise artifact_registry_resource_not_available_error(error) if operation == :mutation

      # A query renders an empty connection here, indistinguishable from a
      # namespace with no repositories. Not logged here: the client logged the
      # rejection when it first raised it. A negative-cache replay logs nothing.
      nil
    end

    def render_artifact_registry_api_error(error, operation, errors)
      message = artifact_registry_api_error_message(error)

      if operation == :mutation
        errors << message
        return
      end

      raise ::Gitlab::Graphql::Errors::BaseError.new(message, extensions: artifact_registry_api_extensions(error))
    end

    def artifact_registry_api_error_message(error)
      message = error.message
      return message if message.present? && message != error.class.name

      s_('ArtifactRegistry|Artifact Registry returned an error.')
    end

    def artifact_registry_service_unavailable_error(error)
      ::Gitlab::Graphql::Errors::ArtifactRegistry::ServiceUnavailable.new(
        s_('ArtifactRegistry|The Artifact Registry service is unavailable.'),
        extensions: artifact_registry_extensions(error)
      )
    end

    def artifact_registry_resource_not_available_error(error)
      ::Gitlab::Graphql::Errors::ResourceNotAvailable.new(
        ::Gitlab::Graphql::Authorize::AuthorizeResource::RESOURCE_ACCESS_ERROR,
        extensions: artifact_registry_extensions(error)
      )
    end

    def artifact_registry_extensions(error)
      { request_id: error.request_id }.compact
    end

    def artifact_registry_api_extensions(error)
      { code: error.code, request_id: error.request_id }.compact
    end
  end
end
