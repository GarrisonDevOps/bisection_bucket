# frozen_string_literal: true

module Gitlab
  module Mcp
    module LegacyProjectArgument
      OTHER_KEY = { 'id' => 'project_id', 'project_id' => 'id' }.freeze
      IID_KEY = /_iid\z/

      class << self
        def normalize!(tool, arguments, _current_user = nil)
          declared = declared_project_key(tool)
          return [] unless declared

          rewrites = []
          other = OTHER_KEY[declared]

          if rename?(tool, arguments, declared, other)
            arguments[declared] = arguments.delete(other)
            rewrites << "#{other}->#{declared}"
          end

          value = arguments[declared]
          if value.is_a?(Integer) && value > 0 && !arguments.key?(other) && string_typed?(tool, declared)
            arguments[declared] = value.to_s
            rewrites << "#{declared}:integer->string"
          end

          rewrites
        end

        private

        def declared_project_key(tool)
          keys = Array(tool.container_arguments[:project]).map(&:to_s) & OTHER_KEY.keys
          keys.first if keys.one?
        end

        def rename?(tool, arguments, declared, other)
          return false if arguments.key?(declared) || !arguments.key?(other)

          properties = schema_properties(tool)
          return false if !properties.key?(declared) || properties.key?(other)

          iid_keys = properties.keys.grep(IID_KEY)
          iid_keys.empty? || iid_keys.any? { |key| arguments.key?(key) }
        end

        def string_typed?(tool, key)
          schema_properties(tool).dig(key, :type) == 'string'
        end

        def schema_properties(tool)
          tool.input_schema.to_h.with_indifferent_access[:properties] || {}
        end
      end
    end
  end
end
