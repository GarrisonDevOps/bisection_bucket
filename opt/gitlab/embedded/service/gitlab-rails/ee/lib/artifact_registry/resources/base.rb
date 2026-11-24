# frozen_string_literal: true

module ArtifactRegistry
  module Resources
    class Base
      include Errors
      include Paths
      include Guards

      def initialize(transport:, reporting:)
        @transport = transport
        @reporting = reporting
      end

      private

      delegate :user_request, :service_request, to: :@transport, private: true
      delegate :log_error, :raise_terminal, to: :@reporting, private: true

      # Reports a 404 as an absence rather than raising. Pass log: true where an unresolvable path is
      # not an ordinary outcome for the caller, so the drift behind it stays diagnosable.
      def nil_on_missing(log: false, **log_context)
        yield
      rescue ApiError => e
        raise unless e.status == 404

        log_error(e, **log_context) if log

        nil
      end

      def success_body(response, expected:, **attribution)
        body = response.body
        return body if body.is_a?(expected)

        raise_unexpected_success(response, **attribution)
      end

      def list_rows(response, slug:)
        attributes_list = success_body(response, expected: Array, slug: slug)
        raise_unexpected_success(response, slug: slug) unless attributes_list.all?(Hash)

        attributes_list
      end

      # Refuses only a body missing an expected key, not one whose value is null: a present key
      # passes through so the reader, not this guard, decides what a null value means.
      def missing_expected_keys?(attributes, *expected_keys)
        expected_keys.any? { |key| !attributes.key?(key) }
      end

      def permissions_query(include_permissions)
        include_permissions ? { include_permissions: true } : {}
      end

      def verdicts(permissions, scope:, read:, slug:, requested:)
        return unless requested
        return Permissions::Verdicts.absent(scope: scope, read: read, slug: slug) unless permissions.is_a?(Hash)

        Permissions::Verdicts.new(permissions, scope: scope, read: read, slug: slug)
      end

      def raise_unexpected_success(response, **attribution)
        raise_terminal(
          UnavailableError,
          'Artifact Registry returned an unexpected success response',
          response.env&.method,
          status: response.status,
          body_class: response.body.class.name,
          **attribution
        )
      end
    end
  end
end
