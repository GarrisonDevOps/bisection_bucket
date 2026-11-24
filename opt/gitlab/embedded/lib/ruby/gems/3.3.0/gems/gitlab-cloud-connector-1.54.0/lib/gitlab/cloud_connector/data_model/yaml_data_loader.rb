# frozen_string_literal: true

require 'yaml'
require_relative 'abstract_data_loader'
require_relative 'overridable'

module Gitlab
  module CloudConnector
    module DataModel
      class YamlDataLoader < AbstractDataLoader
        include Overridable

        protected

        def load!
          Dir.glob(data_files_path).map { |file| load_model_from_file(file) }
        end

        def with_cache
          @name_index ||= yield
        end

        def data_files_path
          File.join(CloudConnector::Configuration.config_dir, model_class.model_name.tableize, '*.yml')
        end

        def load_model_from_file(file_path)
          raw_data = load_yaml_file(file_path)
          data = apply_overrides(raw_data, model_class)

          model_class.new(**data)
        rescue StandardError => e
          raise "Error loading file #{file_path}: #{e.message}"
        end

        def load_yaml_file(file_path)
          YAML.safe_load(
            File.read(file_path),
            permitted_classes: [Time],
            symbolize_names: true
          ) || {}
        end
      end
    end
  end
end
