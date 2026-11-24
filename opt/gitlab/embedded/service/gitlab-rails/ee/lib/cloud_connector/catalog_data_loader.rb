# frozen_string_literal: true

module CloudConnector
  class CatalogDataLoader < Gitlab::CloudConnector::DataModel::AbstractDataLoader
    include Gitlab::Utils::StrongMemoize

    def load_with_index!
      loader.load_with_index!
    end

    def loader
      use_yaml_data_loader? ? yaml_data_loader : database_data_loader
    end

    private

    def use_yaml_data_loader?
      return true if ::Gitlab::Saas.feature_available?(:cloud_connector_static_catalog)
      return true if License.current.nil? || License.current.offline_cloud_license?

      Gitlab::Utils.to_boolean(ENV['CLOUD_CONNECTOR_SELF_SIGN_TOKENS'])
    end

    def yaml_data_loader
      strong_memoize_with(:yaml_data_loader, model_class) do
        ::Gitlab::CloudConnector::DataModel::YamlDataLoader.new(model_class)
      end
    end

    def database_data_loader
      strong_memoize_with(:database_data_loader, model_class) do
        ::CloudConnector::DatabaseDataLoader.new(model_class)
      end
    end
  end
end
