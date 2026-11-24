# frozen_string_literal: true

module ArtifactRegistry
  # Value object for a namespace returned by the AR GitLab API
  # (GET /api/gitlab/v1/namespaces/:uuid). `id` is AR's namespace UUID.
  # `status` is passed through raw and unvalidated so unrecognized values
  # reach the frontend's fallback instead of raising.
  class Namespace < ValueObject
    include TimeCoercion

    PURGED_STATUS = 'purged'

    expose_attribute :id, :slug, :platform, :entity_type, :entity_id, :status

    def created_at
      parse_time(@attributes['created_at'])
    end
  end
end
