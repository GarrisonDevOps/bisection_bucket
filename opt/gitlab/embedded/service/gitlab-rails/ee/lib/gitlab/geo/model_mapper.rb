# frozen_string_literal: true

module Gitlab
  module Geo
    # Finds a Model class associated with a String, which can be a parameter received by a controller
    # The string needs to match the model name, as defined by the Replicators
    #
    # Examples:
    # find_from_name("packages_package_file") returns Packages::PackageFile
    # convert_to_name(Packages::PackageFile) returns "packages_package_file"
    class ModelMapper
      class << self
        # Used by the Replicator to format a model name for API usage
        # @return [String] the snake_case representation of the passed Model class
        def convert_to_name(model)
          model_name_converter(model)
        end

        # Used by the controller to get an ActiveRecord model from a passed parameter
        # @return [Class] the Model class matching the passed string, or nil
        def find_from_name(model_name)
          return unless model_name.is_a?(String)

          model_matching_hash[model_name.downcase]
        end

        def available_models
          list_of_available_models
        end

        def available_replicable_models
          list_of_available_replicable_models
        end

        def available_model_names
          list_of_available_models.map { |model| model_name_converter(model) }
        end

        def available_model_names_pluralized
          available_model_names.map(&:pluralize).freeze
        end

        private

        def model_matching_hash
          Gitlab::SafeRequestStore.fetch(:geo_model_mapper_model_matching_hash) do
            list_of_available_models.index_by { |model| model_name_converter(model) }
          end
        end

        def list_of_available_models
          Gitlab::SafeRequestStore.fetch(:geo_model_mapper_available_model_names_list) do
            Gitlab::Geo::REPLICATOR_CLASSES.map(&:model)
          end
        end

        def list_of_available_replicable_models
          Gitlab::SafeRequestStore.fetch(:geo_model_mapper_replicable_models_list) do
            Gitlab::Geo.replication_enabled_replicator_classes.map(&:model)
          end
        end

        def model_name_converter(model_class)
          ::Gitlab::Utils.param_key(model_class)
        end
      end
    end
  end
end
