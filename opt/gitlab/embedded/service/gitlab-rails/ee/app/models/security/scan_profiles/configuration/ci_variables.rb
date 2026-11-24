# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration
      module CiVariables
        SERIALIZERS = {
          boolean: ->(value) { value ? 'true' : 'false' },
          string: ->(value) { value.to_s },
          integer: ->(value) { value.to_s },
          comma_separated_strings: ->(value) { Array(value).join(',') },
          space_separated_strings: ->(value) { Array(value).join(' ') }
        }.freeze

        def self.build(scan_type, config)
          symbolized = config.to_h.deep_symbolize_keys
          mappings = ScanProfileVariables::MAPPINGS.fetch(scan_type&.to_sym, {})

          mappings.each_with_object({}) do |(key, definition), variables|
            next if symbolized[key].nil?

            variables[definition[:env]] = SERIALIZERS.fetch(definition[:type]).call(symbolized[key])
          end
        end
      end
    end
  end
end
