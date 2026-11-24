# frozen_string_literal: true

module ContainerRegistry
  # Normalizes image labels and annotations read from registry payloads.
  # Keep the limits in step with the registry tag list API, so the details
  # view and the list return the same data for an image:
  # https://gitlab.com/gitlab-org/gitlab/-/work_items/18815
  module MetadataMap
    MAX_ENTRIES = 25
    MAX_VALUE_BYTES = 4096

    def self.sanitize(map)
      return {} unless map.is_a?(Hash)

      entries = map.compact
      return {} unless entries.values.all?(String)

      scrubbed = entries.to_h { |key, value| [key.scrub, value.scrub] }
      scrubbed.sort_by { |key, _| key }.first(MAX_ENTRIES).to_h.transform_values { |value| truncate(value) }
    end

    def self.truncate(value)
      return value if value.bytesize <= MAX_VALUE_BYTES

      value.byteslice(0, MAX_VALUE_BYTES).scrub('')
    end

    private_class_method :truncate
  end
end
