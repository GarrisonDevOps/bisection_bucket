# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- follows existing package_metadata services pattern
  class PackageDataObjectV3 < CompressedPackageDataObjectBase
    MAX_IDENTIFIER_LENGTH = 50
    MAX_EXPRESSION_LENGTH = 1024
    MAX_LICENSE_SET_SIZE = 200

    def self.create(data, purl_type)
      new(data, purl_type)
    end

    def initialize(data, purl_type)
      raise ArgumentError, "record is not an object" unless data.is_a?(Hash)
      raise ArgumentError, "name is required" unless data["name"].is_a?(String) && data["name"].present?

      @purl_type = purl_type
      @name = data["name"]
      @default_identifiers = extract_identifiers(data["default_licenses"])
      @default_expressions = extract_expressions(data["default_licenses"])
      @lowest_version = data["lowest_version"]
      @highest_version = data["highest_version"]
      @raw_other = Array(data["other_licenses"])

      validate_set_sizes!
    end

    attr_reader :default_identifiers, :default_expressions

    def other_licenses
      @other_licenses ||= @raw_other.filter_map do |entry|
        next unless entry.is_a?(Hash)

        {
          'licenses' => extract_identifiers(entry),
          'expressions' => extract_expressions(entry),
          'versions' => Array(entry['versions'])
        }
      end
    end

    def spdx_identifiers
      (default_identifiers + other_licenses.flat_map { |entry| entry['licenses'] }).sort.uniq
    end

    def spdx_expressions
      (default_expressions + other_licenses.flat_map { |entry| entry['expressions'] }).sort.uniq
    end

    private

    def validate_set_sizes!
      sets = [{ 'licenses' => default_identifiers, 'expressions' => default_expressions }] + other_licenses

      return if sets.all? { |set| set['licenses'].size + set['expressions'].size <= MAX_LICENSE_SET_SIZE }

      raise ArgumentError, "license set exceeds #{MAX_LICENSE_SET_SIZE} entries"
    end

    def extract_identifiers(set)
      extract_values(set, "licenses", MAX_IDENTIFIER_LENGTH)
    end

    def extract_expressions(set)
      extract_values(set, "expressions", MAX_EXPRESSION_LENGTH)
    end

    def extract_values(set, key, max_length)
      return [] unless set.is_a?(Hash)

      Array(set[key]).select { |value| usable?(value, max_length) }
    end

    def usable?(value, max_length)
      value.is_a?(String) && value.present? && value.length <= max_length && value.exclude?("\0")
    end
  end
end
