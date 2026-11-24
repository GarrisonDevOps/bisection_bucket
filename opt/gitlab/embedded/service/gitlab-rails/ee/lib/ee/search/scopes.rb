# frozen_string_literal: true

module EE
  module Search
    module Scopes
      # EE-specific global search settings
      EE_GLOBAL_SEARCH_SETTING_MAP = {
        'blobs' => :global_search_code_enabled?,
        'wiki_blobs' => :global_search_wiki_enabled?,
        'commits' => :global_search_commits_enabled?
      }.freeze

      def self.prepended(base)
        class << base
          prepend ClassMethods
        end
      end

      module ClassMethods
        extend ::Gitlab::Utils::Override

        private

        override :global_search_setting_map
        def global_search_setting_map
          super.merge(EE_GLOBAL_SEARCH_SETTING_MAP)
        end

        override :valid_definition?
        def valid_definition?(scope, definition, context, container, requested_search_type = nil)
          availability = definition[:availability]
          return super if availability[context].blank?

          # For blobs ee_search_type_values should have zoekt. advanced only when elasticsearch_code_scope is true
          # For non blobs it should only be advanced
          ee_search_type_values = if scope == :blobs
                                    ::Gitlab::CurrentSettings.elasticsearch_code_scope ? %i[zoekt advanced] : [:zoekt]
                                  else
                                    [:advanced]
                                  end.freeze

          ee_search_types = availability[context].select { |t| ee_search_type_values.include?(t) }

          if ee_search_types.any?
            # If explicitly requesting EE search type
            if requested_search_type.present? && [:zoekt, :advanced].include?(requested_search_type.to_sym)
              return validate_ee_scope(scope, definition, context, container, requested_search_type)
            end

            # If no explicit search type, check if any EE search type is available
            if requested_search_type.blank? && ee_search_types.any? { |t| search_type_available?(t, container) }
              return validate_ee_scope(scope, definition, context, container, nil)
            end
          end

          # For basic search or CE scopes, delegate to CE
          super
        end

        def validate_ee_scope(scope, definition, context, container, requested_search_type)
          availability = definition[:availability]

          # Check global settings
          return false if context == :global && global_search_disabled_for_scope?(scope)

          # Check if search type is available
          if requested_search_type.present?
            return false unless availability[context].include?(requested_search_type.to_sym)

            return search_type_available?(requested_search_type.to_sym, container)
          end

          # Check if any of the available search types are actually available
          availability[context].any? { |available_type| search_type_available?(available_type, container) }
        end

        # Check if a specific search type is available for the container
        # @param search_type [Symbol] :basic, :advanced, or :zoekt
        # @param container [Project, Group, nil] The container being searched
        # @return [Boolean] True if the search type is available
        def search_type_available?(search_type, container)
          case search_type
          when :zoekt
            # Search::Zoekt.search? already checks if nodes/replicas are available
            ::Search::Zoekt.search?(container)
          when :advanced
            ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: container)
          when :basic
            true
          else
            false
          end
        end
      end
    end
  end
end
