# frozen_string_literal: true

module Resolvers
  module Security
    class ScanProfileVariablesResolver < BaseResolver
      type [Types::Security::ScanProfiles::VariableType], null: false
      description 'Configuration variables a scan profile of the given type can set.'

      argument :scan_type, Types::Security::ScanProfileTypeEnum,
        required: true,
        description: 'Scan profile type to return the configuration variables for.'

      VALUE_TYPES = {
        boolean: :boolean,
        string: :string,
        integer: :integer,
        comma_separated_strings: :string_list,
        space_separated_strings: :string_list
      }.freeze

      def resolve(scan_type:)
        mappings = ::Security::ScanProfiles::Configuration::ScanProfileVariables::MAPPINGS.fetch(scan_type.to_sym, {})

        mappings.map do |key, mapping|
          {
            key: key.to_s.camelize(:lower),
            env_var: mapping[:env],
            label: s_(mapping[:label]),
            description: s_(mapping[:description]),
            value_type: value_type(mapping),
            options: mapping[:options]&.map { |option| { value: option[:value], text: s_(option[:text]) } },
            placeholder: mapping[:placeholder_text] ? s_(mapping[:placeholder_text]) : mapping[:placeholder],
            min: mapping[:min],
            max: mapping[:max]
          }
        end
      end

      private

      def value_type(mapping)
        value_type = VALUE_TYPES.fetch(mapping[:type])
        return value_type unless mapping[:options]

        value_type == :string_list ? :multi_select : :enum
      end
    end
  end
end
