# frozen_string_literal: true

module ArtifactRegistry
  class MavenFile < ValueObject
    include TimeCoercion

    expose_attribute :id, :file_name, :size, :sha256, :sha1, :sha512

    # Nullable in the contract: a deploy may store no MD5.
    expose_attribute :md5

    # Nullable: the Maven file resource may omit the timestamp, so it coerces to nil.
    def created_at
      parse_time(@attributes['created_at'])
    end
  end
end
