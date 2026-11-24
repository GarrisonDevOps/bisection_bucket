# frozen_string_literal: true

module ArtifactRegistry
  module Guards
    MAX_VERIFICATION_BATCH = 1000
    MAX_BULK_DELETE_BATCH = 1000
    UUID_REGEX = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/
    NOT_PROVIDED = Object.new.freeze
    # AR ids are UUIDs (36 bytes) and digests sha256 (71 bytes); 256 bytes leaves headroom.
    MAX_DEEP_LINK_BYTES = 256

    private

    def guard_format!(format, allowed)
      raise ArgumentError, "format must be one of: #{allowed.join(', ')}" if allowed.exclude?(format)
    end

    def guard_present!(**fields)
      fields.each do |field, value|
        raise ArgumentError, "#{field} is required" if value.blank? || value.equal?(NOT_PROVIDED)
      end
    end

    def provided_fields(**fields)
      fields.reject { |_field, value| value.equal?(NOT_PROVIDED) }
    end

    def guard_segments!(**segments)
      guard_present!(**segments)

      segments.each do |segment, value|
        raise ArgumentError, "#{segment} must not be a bare '.' or '..' segment" if dot_segment?(value)
      end
    end

    def guard_uuid!(**fields)
      fields.each do |field, value|
        raise ArgumentError, "#{field} must be a UUID" unless value.to_s.match?(UUID_REGEX)
      end
    end

    def dot_segment?(value)
      value.to_s == '.' || value.to_s == '..'
    end

    # Callers return nil, not raise, so a bad deep link looks like a 404 (no id-syntax oracle).
    def malformed_deep_link?(*values)
      values.any? { |value| value.blank? || dot_segment?(value) || value.to_s.bytesize > MAX_DEEP_LINK_BYTES }
    end

    def guard_batch!(name, list, max)
      return if list.is_a?(Array) && list.size.between?(1, max)

      raise ArgumentError, "#{name} must carry between 1 and #{max} entries"
    end

    # repository_ids also go to IAM, which accepts only UUIDv7; namespace_id only goes to AR.
    def guard_verification_input!(namespace_id, repository_ids)
      raise ArgumentError, 'namespace_id must be a canonical UUID' unless canonical_uuid?(namespace_id)

      guard_batch!(:repository_ids, repository_ids, MAX_VERIFICATION_BATCH)

      return if repository_ids.all? { |id| ::Gitlab::UUID.v7?(id) }

      raise ArgumentError, 'repository_ids must be canonical UUIDv7s'
    end

    def canonical_uuid?(value)
      value.is_a?(String) && value.match?(UUID_REGEX) && value == value.downcase
    end
  end
end
