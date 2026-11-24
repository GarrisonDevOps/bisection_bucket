# frozen_string_literal: true

module Geo
  module Replicator
    # Pure naming derivations shared by the Geo replicator generators. Built from the replicable
    # name (NAME -> file_name/class_name) plus a few options; holds no Thor/filesystem state, so it
    # is unit-testable in isolation.
    class Naming
      def initialize(file_name:, class_name:, model_class:, upload_partition:, parent_factory:)
        @file_name = file_name
        @class_name = class_name
        @model_class = model_class
        @upload_partition = upload_partition
        @parent_factory = parent_factory
      end

      attr_reader :file_name, :class_name

      def replicable_title
        file_name.split('_').map(&:capitalize).join(' ')
      end

      def replicable_title_plural
        "#{replicable_title}s"
      end

      def registry_table_name
        "#{file_name}_registry"
      end

      def state_table_name
        "#{file_name}_states"
      end

      def foreign_key_name
        "#{file_name}_id"
      end

      def registry_class_name
        "#{class_name}Registry"
      end

      def replicator_class_name
        "#{class_name}Replicator"
      end

      def state_class_name
        "#{class_name}State"
      end

      def finder_class_name
        "#{class_name}RegistryFinder"
      end

      def resolver_class_name
        "#{class_name}RegistriesResolver"
      end

      def registry_type_class_name
        "#{class_name}RegistryType"
      end

      def enum_key
        registry_table_name.upcase
      end

      def registry_factory_replicable_name
        @upload_partition ? "geo_#{file_name}" : file_name
      end

      def graphql_field_name
        "#{file_name}_registries"
      end

      def graphql_field_name_camel
        parts = file_name.split('_')
        parts[0] + parts[1..].map(&:capitalize).join
      end

      def graphql_registries_field_camel
        "#{graphql_field_name_camel}Registries"
      end

      def graphql_foreign_key_field_camel
        "#{graphql_field_name_camel}Id"
      end

      def replication_feature_flag_name
        "geo_#{file_name}_replication"
      end

      def force_primary_checksumming_feature_name
        "geo_#{file_name}_force_primary_checksumming"
      end

      def model_factory_name
        @model_class.split('::').last.underscore
      end

      def parent_model_factory_name
        @parent_factory.presence || file_name.sub(/_upload$/, '')
      end
    end
  end
end
