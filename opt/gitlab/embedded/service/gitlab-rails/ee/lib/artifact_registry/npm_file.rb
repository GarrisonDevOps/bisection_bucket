# frozen_string_literal: true

module ArtifactRegistry
  class NpmFile < ValueObject
    include TimeCoercion

    expose_attribute :id, :file_name, :size, :sha256

    # Nullable: the contract serializes it on a hosted row and null on a remote
    # cached one, which carries no per-file time of its own.
    def created_at
      parse_time(@attributes['created_at'])
    end
  end
end
