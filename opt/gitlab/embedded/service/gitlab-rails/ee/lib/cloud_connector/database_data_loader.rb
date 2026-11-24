# frozen_string_literal: true

module CloudConnector
  class DatabaseDataLoader < Gitlab::CloudConnector::DataModel::AbstractDataLoader
    include ::CloudConnector::Utils

    DATE_FIELDS = %w[cut_off_date].freeze
    CATALOG_STORE_KEY = 'cloud_connector:catalog_json'
    ASSOCIATION_SUFFIX = '_association'

    protected

    def load!
      if catalog_data.empty?
        log_warning("Catalog is empty or not synced")

        return []
      end

      model_attributes = catalog_data[model_name]

      if model_attributes.blank?
        log_warning("Catalog key '#{model_name}' is missing or empty")

        return []
      end

      model_attributes.map { |raw_attributes| model_class.new(**transform_attributes(raw_attributes)) }
    end

    def with_cache
      Gitlab::SafeRequestStore.fetch(cache_key) { yield }
    end

    def transform_attributes(raw_attributes)
      attributes = raw_attributes.dup

      attributes.reject! { |key, _| key.to_s.end_with?(ASSOCIATION_SUFFIX) }

      DATE_FIELDS.each do |field|
        attributes[field] = parse_time(attributes[field]) if attributes.key?(field)
      end

      attributes
    end

    def catalog_data
      Gitlab::SafeRequestStore.fetch(CATALOG_STORE_KEY) do
        CloudConnector::Access.last&.catalog || {}
      end
    end

    def model_name
      @model_name ||= model_class.model_name.tableize
    end

    def cache_key
      @cache_key ||= "#{self.class.name.underscore.tr('/', ':')}:#{model_name}"
    end

    def log_warning(message)
      ::Gitlab::AppLogger.warn(message: message, class_name: self.class.name)
    end
  end
end
