# frozen_string_literal: true

module Search
  module Elastic
    class QueryBuilder
      include ::Elastic::Latest::QueryContext::Aware

      QUERY_COMPONENTS = {}.freeze

      SCORE_COMPONENTS = {}.freeze

      def self.build(...)
        new(...).build
      end

      def initialize(query:, options: {})
        @query = query
        # allow extra_options to overwrite base_options
        @options = options.merge(base_options.merge(extra_options))
      end

      def build
        prepare_options

        query_hash = build_initial_query_hash
        deferred = []

        self.class::QUERY_COMPONENTS.each do |builder_class, methods|
          methods.each do |method|
            if method.is_a?(Hash)
              method, migration, unless_migration, skip_if_size_zero = method.values_at(:method, :migration,
                :unless_migration, :skip_if_size_zero)
            end

            next if migration && !::Elastic::DataMigrationService.migration_has_finished?(migration)
            next if unless_migration && ::Elastic::DataMigrationService.migration_has_finished?(unless_migration)

            if skip_if_size_zero
              deferred << [builder_class, method]
            else
              # rubocop:disable GitlabSecurity/PublicSend -- Not user-input
              query_hash = builder_class.public_send(method, query_hash: query_hash, options: options)
              # rubocop:enable GitlabSecurity/PublicSend
            end
          end
        end

        return query_hash if query_hash[:size] == 0

        deferred.each do |builder_class, method|
          # rubocop:disable GitlabSecurity/PublicSend -- Not user-input
          query_hash = builder_class.public_send(method, query_hash: query_hash, options: options)
          # rubocop:enable GitlabSecurity/PublicSend
        end

        apply_components(self.class::SCORE_COMPONENTS, query_hash)
      end

      private

      attr_reader :query, :options

      def apply_components(components, query_hash)
        components.each do |builder_class, methods|
          methods.each do |method|
            if method.is_a?(Hash)
              method, migration, unless_migration = method.values_at(:method, :migration, :unless_migration)
            end

            next if migration && !::Elastic::DataMigrationService.migration_has_finished?(migration)
            next if unless_migration && ::Elastic::DataMigrationService.migration_has_finished?(unless_migration)

            # rubocop:disable GitlabSecurity/PublicSend -- Not user-input
            query_hash = builder_class.public_send(method, query_hash: query_hash, options: options)
            # rubocop:enable GitlabSecurity/PublicSend
          end
        end

        query_hash
      end

      def base_options
        {
          project_id_field: :project_id,
          project_visibility_level_field: :visibility_level,
          namespace_visibility_level_field: :namespace_visibility_level,
          no_join_project: true,
          source_fields: ['id']
        }
      end

      # Subclasses should override this method to provide additional options to builder
      def extra_options
        {}
      end

      # Subclasses should override to set options before the build pipeline runs
      def prepare_options; end

      # Subclasses without a text query return a blank bool expression.
      # Subclasses with a text query (e.g. full-text or fuzzy) should override this.
      def build_initial_query_hash
        { query: { bool: ::Search::Elastic::BoolExpr.new } }
      end
    end
  end
end
