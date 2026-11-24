# frozen_string_literal: true

module ArtifactRegistry
  class Image < ValueObject
    include TimeCoercion

    expose_attribute :id, :name

    def last_downloaded_at
      parse_time(@attributes['last_downloaded_at'])
    end
  end
end
