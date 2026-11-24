# frozen_string_literal: true

module ArtifactRegistry
  class NpmPackage < ValueObject
    include TimeCoercion

    expose_attribute :id, :name, :scope, :versions_count

    def last_downloaded_at
      parse_time(@attributes['last_downloaded_at'])
    end
  end
end
