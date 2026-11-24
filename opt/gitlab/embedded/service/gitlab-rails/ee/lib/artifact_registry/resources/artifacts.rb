# frozen_string_literal: true

module ArtifactRegistry
  module Resources
    class Artifacts < Base
      # @return [void]
      def bulk_delete_artifacts(slug:, repository_name:, format:)
        guard_format!(format, Formats::ARTIFACT_FORMATS)
        guard_segments!(slug: slug, repository_name: repository_name)

        path = bulk_delete_path(slug, repository_name, format, Formats.collection(format))

        response = user_request(:post, path, slug: slug, body: { delete_all: true })

        # The 202 is the whole outcome: no body, no job handle, so there is nothing to hand back.
        # Another 2xx is contract drift rather than an acceptance, so refuse it instead of reading
        # it as one, which matters most here because this route addresses the whole collection.
        raise_unexpected_success(response, slug: slug) unless response.status == 202

        nil
      end

      # @return [void]
      def delete_artifact(slug:, repository_name:, format:, id:)
        guard_format!(format, Formats::ARTIFACT_FORMATS)
        # Guarded here rather than resolved to a not-found the way the single-artifact reads do:
        # without this an id-less delete would silently build a path with an empty final segment.
        guard_segments!(slug: slug, repository_name: repository_name, id: id)

        path = artifact_path(slug, repository_name, format, Formats.collection(format), id)

        response = user_request(:delete, path, slug: slug)

        raise_unexpected_success(response, slug: slug) unless response.status == 202

        nil
      end
    end
  end
end
