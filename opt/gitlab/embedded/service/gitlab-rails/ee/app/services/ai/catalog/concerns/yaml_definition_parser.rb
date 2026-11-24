# frozen_string_literal: true

module Ai
  module Catalog
    module Concerns
      module YamlDefinitionParser
        extend ActiveSupport::Concern
        include Gitlab::Utils::StrongMemoize

        private

        def definition_parsed
          return unless params[:definition].present?

          parsed = YAML.safe_load(params[:definition])
          return unless parsed.is_a?(Hash)

          parsed.merge(yaml_definition: params[:definition])
        rescue Psych::Exception
          nil
        end
        strong_memoize_attr :definition_parsed

        def valid_yaml_definition?
          return true unless params.key?(:definition)

          definition_parsed.present?
        end

        def yaml_syntax_error(item_type = 'Flow')
          error("#{item_type} definition does not have a valid YAML syntax")
        end

        def yaml_definition_error(item_type = 'Flow')
          strong_memoize_with(:yaml_definition_error, item_type) do
            if ItemVersion.yaml_definition_too_large?(params[:definition])
              next error(ItemVersion.yaml_size_error_message)
            end

            yaml_syntax_error(item_type) unless valid_yaml_definition?
          end
        end

        def parsed_yaml_definition_or_error(item_type = 'Flow')
          return yaml_syntax_error(item_type) unless valid_yaml_definition?

          definition_parsed
        end

        def parsed_definition_param
          return {} unless should_update_definition?

          { definition: definition_parsed }
        end

        def should_update_definition?
          params.key?(:definition) && definition_parsed.present?
        end

        def use_object_storage_for_yaml_definition?
          Feature.enabled?(:ai_catalog_yaml_object_storage, project)
        end
      end
    end
  end
end
