# frozen_string_literal: true

module Analytics
  module AggregationEngines
    module Support
      # Builds the base scope of an engine for given projects, groups, org
      module BaseAggregationScope
        extend ActiveSupport::Concern

        included do
          class_attribute :scope_path_column, default: :traversal_path
          class_attribute :scope_path_with_organization, default: true
        end

        class_methods do
          def prepare_base_aggregation_scope(objects)
            builder = ClickHouse::Client::QueryBuilder.new(table_name)

            conditions = Array.wrap(objects).map { |object| scope_condition(builder, object) }

            raise ArgumentError, 'at least one scope object is required' if conditions.empty?

            # A nil condition selects every row of the table.
            return builder if conditions.any?(&:nil?)

            builder.where(conditions.reduce(:or))
          end

          private

          def scope_condition(builder, object)
            if object.is_a?(::Organizations::Organization)
              return if only_organization?(object)

              unless scope_path_with_organization
                raise ArgumentError, 'organization scope requires an instance with a single organization'
              end
            end

            namespace = object.is_a?(::Project) ? object.project_namespace : object
            path = namespace.traversal_path(with_organization: scope_path_with_organization)

            builder.func('startsWith', [builder[scope_path_column], Arel::Nodes.build_quoted(path)])
          end

          def only_organization?(organization)
            !::Organizations::Organization.id_not_in(organization.id).exists?
          end
        end
      end
    end
  end
end
