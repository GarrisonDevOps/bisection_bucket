# frozen_string_literal: true

module ArtifactRegistry
  class MavenPackage < ValueObject
    include TimeCoercion

    expose_attribute :id, :group_id, :artifact_id

    def last_downloaded_at
      parse_time(@attributes['last_downloaded_at'])
    end
  end
end
