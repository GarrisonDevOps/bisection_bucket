# frozen_string_literal: true

module Gitlab
  module CloudConnector
    module Configuration
      DEFAULT_DATA_LOADER_CLASS = Gitlab::CloudConnector::DataModel::YamlDataLoader
      INVALID_LOADER_MESSAGE = "Data loader must inherit from Gitlab::CloudConnector::DataModel::AbstractDataLoader"
      INVALID_CONFIG_MESSAGE = "Override configuration must be a Hash or respond to :call"

      InvalidDataLoaderError = Class.new(StandardError)
      InvalidConfigError = Class.new(StandardError)

      class << self
        attr_writer :config_dir
        attr_reader :override_config

        def config_dir
          @config_dir ||= (ENV["CLOUD_CONNECTOR_CONFIG_DIR"] || File.expand_path("../../../config", __dir__)).freeze
        end

        def data_loader_class
          @data_loader_class ||= DEFAULT_DATA_LOADER_CLASS
        end

        def data_loader_class=(klass)
          validate_data_loader!(klass)
          @data_loader_class = klass
        end

        def override_config=(value)
          validate_override_config!(value)
          @override_config = value
        end

        def configure
          yield self if block_given?
        end

        private

        def validate_data_loader!(klass)
          return if klass && klass < Gitlab::CloudConnector::DataModel::AbstractDataLoader

          raise InvalidDataLoaderError, INVALID_LOADER_MESSAGE
        end

        def validate_override_config!(value)
          return if value.nil? || value.is_a?(Hash) || value.respond_to?(:call)

          raise InvalidConfigError, INVALID_CONFIG_MESSAGE
        end
      end
    end
  end
end
