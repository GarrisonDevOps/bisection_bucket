# frozen_string_literal: true

module ArtifactRegistry
  module Resources
    class Upstreams < Base
      def upstream_repositories(slug:, repository_name:, format:, include_permissions: false)
        guard_format!(format, Formats::ARTIFACT_FORMATS)
        guard_segments!(slug: slug, repository_name: repository_name)

        path = artifacts_path(slug, repository_name, format, 'upstream_repositories')

        nil_on_missing(log: true, slug: slug) do
          response = user_request(:get, path, slug: slug, query: permissions_query(include_permissions))
          attributes_list = list_rows(response, slug: slug)

          attributes_list.map do |attributes|
            UpstreamRepositoryAssociation.new(attributes,
              upstream_verdicts(attributes, slug: slug, requested: include_permissions))
          end
        end
      end

      def dissociate_upstream_repository(slug:, repository_name:, format:, association_id:)
        guard_format!(format, Formats::ARTIFACT_FORMATS)
        guard_segments!(slug: slug, repository_name: repository_name, association_id: association_id)

        upstream_repository_path = artifact_path(slug, repository_name, format, 'upstream_repositories', association_id)

        response = user_request(:delete, upstream_repository_path, slug: slug)

        raise_unexpected_success(response, slug: slug) unless response.status == 204

        true
      rescue ApiError => e
        if e.status == 404 && e.code == 'not_found'
          log_error(e, method: :delete, code: e.code, slug: slug, path: upstream_repository_path)
          return true
        end

        raise
      end

      def test_upstream_connection(slug:, name:)
        guard_segments!(slug: slug, name: name)

        response = user_request(:post, repository_test_path(slug, name), slug: slug)
        attributes = success_body(response, expected: Hash, slug: slug)

        raise_unexpected_success(response, slug: slug) if missing_verdict?(attributes)

        ConnectionTestResult.new(attributes)
      end

      def test_namespace_upstream_connection(slug:, format:, url:, credentials: nil)
        guard_format!(format, Formats::ARTIFACT_FORMATS)
        guard_segments!(slug: slug)
        guard_present!(url: url)

        body = { format: format, url: url, credentials: credentials }.compact
        response = user_request(:post, connection_test_path(slug), slug: slug, body: body)
        attributes = success_body(response, expected: Hash, slug: slug)

        raise_unexpected_success(response, slug: slug) if missing_verdict?(attributes)

        NamespaceConnectionTestResult.new(attributes)
      end

      private

      def upstream_verdicts(attributes, slug:, requested:)
        summary = attributes['upstream_repository']
        permissions = summary['permissions'] if summary.is_a?(Hash)

        verdicts(permissions, scope: :repository, read: :upstream_repositories, slug: slug, requested: requested)
      end

      def missing_verdict?(attributes)
        attributes['passed'].nil?
      end
    end
  end
end
