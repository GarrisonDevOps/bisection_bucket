# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SessionArtifacts
      class ClickHouseFinder
        # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord but ClickHouse query builder
        TABLE_NAME = 'siphon_duo_workflows_workflows'

        # Columns projected from the deduplicated inner query.
        # Only include columns actually used by SessionArtifactType.
        COLUMNS = %i[
          id workflow_definition agent_type project_id namespace_id traversal_path created_at updated_at user_id
        ].freeze

        # Primary key columns used for GROUP BY in the deduplication query.
        # Must match the table's ORDER BY: (traversal_path, created_at, id).
        GROUP_BY_COLUMNS = %i[traversal_path created_at id].freeze

        VERSION_COLUMN = :_siphon_replicated_at
        DELETED_COLUMN = :_siphon_deleted
        MESSAGING_CONTEXT_COLUMN = :messaging_callback_context
        MESSAGING_ADAPTER_ALIAS = :messaging_adapter

        def initialize(namespace:, params: {})
          @namespace = namespace
          @params = params
        end

        def execute
          project_paths = resolve_project_paths
          return empty_query if project_paths[:no_results]

          query = build_base_query(
            include_traversal_path: project_paths[:inclusion],
            exclude_traversal_path: project_paths[:exclusion]
          )
          query = filter_by_workflow_definition(query)
          query = filter_by_agent_type(query)
          query = filter_by_workflow_id(query)
          query = filter_by_created_at(query)
          query = filter_by_user(query)
          query
            .order(:updated_at, :desc)
            .order(:id, :desc)
        end

        private

        attr_reader :namespace, :params

        # Builds a deduplicated base query scoped to the namespace.
        #
        # `siphon_duo_workflows_workflows` uses ReplacingMergeTree with
        # `_siphon_replicated_at` as the version column. Duplicate rows for the
        # same primary key (traversal_path, created_at, id) can exist until the
        # background merge completes. We use `argMax` + GROUP BY to pick the
        # latest version of each row and filter deleted rows in the outer query.
        #
        # Project path filters are pushed into the inner query as `traversal_path`
        # prefix conditions so ClickHouse can use the primary key index before
        # performing the `argMax` + GROUP BY deduplication work.
        def build_base_query(include_traversal_path: nil, exclude_traversal_path: nil)
          builder = ClickHouse::Client::QueryBuilder.new(TABLE_NAME)

          inner_projections = COLUMNS.map do |column|
            if GROUP_BY_COLUMNS.include?(column)
              builder.table[column]
            else
              Arel::Nodes::NamedFunction.new('argMax', [
                builder.table[column],
                builder.table[VERSION_COLUMN]
              ]).as(column.to_s)
            end
          end

          inner_projections << Arel::Nodes::NamedFunction.new('argMax', [
            builder.table[DELETED_COLUMN],
            builder.table[VERSION_COLUMN]
          ]).as(DELETED_COLUMN.to_s)

          inner_projections << messaging_adapter_projection(builder)

          inner_query = builder
            .select(*inner_projections)
            .where(namespace_traversal_path_condition(builder))
            .group(*GROUP_BY_COLUMNS)

          if include_traversal_path.present?
            inner_query = inner_query.where(
              Arel::Nodes::NamedFunction.new('startsWith', [
                builder.table[:traversal_path],
                Arel::Nodes.build_quoted(include_traversal_path)
              ])
            )
          end

          if exclude_traversal_path.present?
            inner_query = inner_query.where(
              Arel::Nodes::NamedFunction.new('not', [
                Arel::Nodes::NamedFunction.new('startsWith', [
                  builder.table[:traversal_path],
                  Arel::Nodes.build_quoted(exclude_traversal_path)
                ])
              ])
            )
          end

          outer_query = ClickHouse::Client::QueryBuilder
            .new(TABLE_NAME)
            .select(*COLUMNS)
            .from(inner_query, TABLE_NAME)
            .where(DELETED_COLUMN => false)

          private_keys = ::Ai::Messaging::AdapterRegistry.private_to_invoker_keys
          return outer_query if private_keys.empty?

          outer_query.where(
            Arel::Nodes::NamedFunction.new('not', [
              outer_query.table[MESSAGING_ADAPTER_ALIAS].in(private_keys)
            ])
          )
        end

        def messaging_adapter_projection(builder)
          Arel::Nodes::NamedFunction.new('JSONExtractString', [
            Arel::Nodes::NamedFunction.new('argMax', [
              Arel::Nodes::NamedFunction.new('coalesce', [
                builder.table[MESSAGING_CONTEXT_COLUMN],
                Arel::Nodes.build_quoted('{}')
              ]),
              builder.table[VERSION_COLUMN]
            ]),
            Arel::Nodes.build_quoted('adapter')
          ]).as(MESSAGING_ADAPTER_ALIAS.to_s)
        end

        def namespace_traversal_path_condition(builder)
          Arel::Nodes::NamedFunction.new('startsWith', [
            builder.table[:traversal_path],
            Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: true))
          ])
        end

        # Resolves project_path params to traversal paths for index-friendly
        # pushdown into the inner deduplication query.
        # Returns { inclusion: String|nil, exclusion: String|nil, no_results: Boolean }
        def resolve_project_paths
          inclusion_path = params[:project_path]
          exclusion_path = not_param(:project_path)

          paths = [inclusion_path, exclusion_path].compact
          return { inclusion: nil, exclusion: nil, no_results: false } if paths.empty?

          resolved = ::Project.where_full_path_in(paths).index_by(&:full_path)

          inclusion_traversal = nil
          if inclusion_path.present?
            project = resolved[inclusion_path]

            return { inclusion: nil, exclusion: nil, no_results: true } if project.nil?

            inclusion_traversal = project.project_namespace.traversal_path(with_organization: true)
          end

          exclusion_traversal = nil
          if exclusion_path.present?
            project = resolved[exclusion_path]
            # If the exclusion path does not resolve, there is nothing to exclude,
            # so we return nil to skip the filter and return all namespace results.
            exclusion_traversal = project&.project_namespace&.traversal_path(with_organization: true)
          end

          { inclusion: inclusion_traversal, exclusion: exclusion_traversal, no_results: false }
        end

        def empty_query
          # ClickHouse has no simple LIMIT 0 short-circuit, so the id = 0 guarantees no rows
          # since siphon IDs are always positive integers.
          ClickHouse::Client::QueryBuilder
            .new(TABLE_NAME)
            .where(id: 0)
        end

        def filter_by_workflow_definition(query)
          if params[:workflow_definition].present?
            query = query.where(workflow_definition: params[:workflow_definition])
          end

          if not_param(:workflow_definition).present?
            query = query.where(query.table[:workflow_definition].not_eq(not_param(:workflow_definition)))
          end

          query
        end

        # `agent_type` is already deduplicated by the inner projection, so this
        # filters the outer query.
        def filter_by_agent_type(query)
          case params[:agent_type_filter]
          when :any then query.where(query.table[:agent_type].not_eq(nil))
          when :none then query.where(query.table[:agent_type].eq(nil))
          else query
          end
        end

        def filter_by_workflow_id(query)
          # The CH table's `id` column IS the workflow (session) id.
          return query unless params[:workflow_id].present?

          query.where(id: params[:workflow_id])
        end

        def filter_by_created_at(query)
          if params[:workflow_created_after].present?
            query = query.where(query.table[:created_at].gteq(format_time(params[:workflow_created_after])))
          end

          if params[:workflow_created_before].present?
            query = query.where(query.table[:created_at].lteq(format_time(params[:workflow_created_before])))
          end

          query
        end

        def filter_by_user(query)
          query = query.where(user_id: params[:user_id]) if params[:user_id].present?
          query = query.where(query.table[:user_id].not_eq(not_param(:user_id))) if not_param(:user_id).present?
          query
        end

        def format_time(time)
          time.utc.strftime('%Y-%m-%d %H:%M:%S')
        end

        def not_param(key)
          params.dig(:not, key)
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
