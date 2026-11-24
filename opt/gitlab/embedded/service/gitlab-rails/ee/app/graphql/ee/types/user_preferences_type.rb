# frozen_string_literal: true

module EE
  module Types
    module UserPreferencesType # rubocop:disable Gitlab/BoundedContexts -- EE extension of existing class
      extend ActiveSupport::Concern

      prepended do
        field :duo_default_namespace,
          ::Types::NamespaceType,
          null: true,
          method: :duo_default_namespace_with_fallback,
          description: 'Default namespace context for Duo features when namespace cannot be inferred.',
          skip_type_authorization: [:read_namespace]

        field :knowledge_graph_governing_namespace,
          ::Types::NamespaceType,
          null: true,
          method: :knowledge_graph_governing_namespace_with_fallback,
          description: 'Governing and billing namespace for Orbit.',
          skip_type_authorization: [:read_namespace]
      end

      def orbit_settings
        object.effective_orbit_settings
      end
    end
  end
end
