# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class PythonConda < Base
          def self.file_name_glob
            'environment.yml'
          end

          def self.lang_name
            'Python'
          end

          private

          ### Example format:
          #
          # name: machine-learning-env
          #
          # dependencies:
          #   - ipython
          #   - matplotlib
          #   - pandas=1.0
          #   - scikit-learn=0.22
          #
          def extract_libs
            parsed = YAML.safe_load(content)

            dig_in(parsed, 'dependencies').try(:map) do |dep|
              name, version = dep.try(:split, '=')
              Lib.new(name: name, version: version)
            end
          rescue Psych::SyntaxError
            raise ParsingErrors::DeserializationException, 'content is not valid YAML'
          rescue Psych::Exception => e
            raise ParsingErrors::DeserializationException, "YAML exception - #{e.message}"
          end
        end
      end
    end
  end
end
