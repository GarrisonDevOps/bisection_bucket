# frozen_string_literal: true

module Ai
  module Governance
    module Sessions
      class ClickHouseFinder
        # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord but ClickHouse query builder
        TABLE_NAME = 'siphon_ai_governance_sessions'

        COLUMNS = %i[
          id namespace_id project_id user_id workflow_id created_at updated_at session_started_at
          session_finished_at source status external_xid agent_type flow_type traversal_path
        ].freeze

        # Must match the table's primary key: (traversal_path, session_started_at, id).
        GROUP_BY_COLUMNS = %i[traversal_path session_started_at id].freeze

        VERSION_COLUMN = :_siphon_replicated_at
        DELETED_COLUMN = :_siphon_deleted

        INTERNAL_SOURCES = %w[gitlab_duo].freeze

        # @param current_user [User]
        # @param namespace [Namespace] group, or the project namespace for a project-scoped listing
        # @param params [Hash] same filters as Ai::Governance::SessionsFinder
        def initialize(current_user:, namespace:, params: {})
          @current_user = current_user
          @namespace = namespace
          @params = params
        end

        # Returns sessions in the namespace and its descendants, newest first.
        #
        # @return [ClickHouse::Client::QueryBuilder]
        def execute
          return empty_query unless allowed?

          project_paths = resolve_project_paths
          return empty_query if project_paths[:no_results]

          query = build_base_query(project_paths)
          query = filter_by_agent_class(query)
          query = filter_by_flow_type(query)
          query = filter_by_user(query)
          query
            .order(:session_started_at, :desc)
            .order(:id, :desc)
        end

        private

        attr_reader :current_user, :namespace, :params

        def allowed?
          Ability.allowed?(current_user, :read_agent_artifacts, namespace)
        end

        # ReplacingMergeTree keeps older versions of a row until a background merge runs, so the inner
        # query picks the latest version of each row with argMax. Conditions on primary key columns go
        # in the inner query so ClickHouse can skip granules before deduplicating.
        def build_base_query(project_paths)
          builder = ClickHouse::Client::QueryBuilder.new(TABLE_NAME)

          inner_query = builder
            .select(*inner_projections(builder))
            .where(starts_with(builder, namespace.traversal_path(with_organization: true)))
            .group(*GROUP_BY_COLUMNS)

          inner_query = inner_query.where(starts_with(builder, project_paths[:inclusion])) if project_paths[:inclusion]

          if project_paths[:exclusion]
            inner_query = inner_query.where(
              Arel::Nodes::NamedFunction.new('not', [starts_with(builder, project_paths[:exclusion])])
            )
          end

          inner_query = inner_query.where(id: params[:id]) if params[:id].present?
          inner_query = filter_by_session_started_at(inner_query)

          ClickHouse::Client::QueryBuilder
            .new(TABLE_NAME)
            .select(*COLUMNS)
            .from(inner_query, TABLE_NAME)
            .where(DELETED_COLUMN => false)
        end

        def inner_projections(builder)
          projections = COLUMNS.map do |column|
            next builder.table[column] if GROUP_BY_COLUMNS.include?(column)

            arg_max(builder, column)
          end

          projections << arg_max(builder, DELETED_COLUMN)
        end

        def arg_max(builder, column)
          Arel::Nodes::NamedFunction.new('argMax', [builder.table[column], builder.table[VERSION_COLUMN]])
            .as(column.to_s)
        end

        def starts_with(builder, path)
          Arel::Nodes::NamedFunction.new('startsWith', [builder.table[:traversal_path], Arel::Nodes.build_quoted(path)])
        end

        # An unresolvable inclusion path matches nothing; an unresolvable exclusion path excludes nothing.
        def resolve_project_paths
          inclusion_path = params[:project_path]
          exclusion_path = not_param(:project_path)

          paths = [inclusion_path, exclusion_path].compact
          return { inclusion: nil, exclusion: nil, no_results: false } if paths.empty?

          resolved = ::Project.where_full_path_in(paths).index_by(&:full_path)

          included = resolved[inclusion_path]
          return { inclusion: nil, exclusion: nil, no_results: true } if inclusion_path.present? && included.nil?

          {
            inclusion: included&.project_namespace&.traversal_path(with_organization: true),
            exclusion: resolved[exclusion_path]&.project_namespace&.traversal_path(with_organization: true),
            no_results: false
          }
        end

        def empty_query
          # Siphon ids are always positive, so `id = 0` matches no rows.
          ClickHouse::Client::QueryBuilder.new(TABLE_NAME).where(id: 0)
        end

        def filter_by_agent_class(query)
          case params[:agent_class]
          when :internal_dap then query.where(source: source_values(INTERNAL_SOURCES))
          when :external then query.where(source: source_values(external_sources))
          else query
          end
        end

        def filter_by_flow_type(query)
          query = query.where(flow_type: params[:flow_type]) if params[:flow_type].present?

          if not_param(:flow_type).present?
            # flow_type is nullable, and `flow_type != X` would silently drop the NULL rows.
            query = query.where(
              query.table[:flow_type].eq(nil).or(query.table[:flow_type].not_eq(not_param(:flow_type)))
            )
          end

          query
        end

        def filter_by_session_started_at(query)
          if params[:session_started_after].present?
            query = query.where(query.table[:session_started_at].gteq(format_time(params[:session_started_after])))
          end

          if params[:session_started_before].present?
            query = query.where(query.table[:session_started_at].lteq(format_time(params[:session_started_before])))
          end

          query
        end

        def filter_by_user(query)
          query = query.where(user_id: params[:user_id]) if params[:user_id].present?
          query = query.where(query.table[:user_id].not_eq(not_param(:user_id))) if not_param(:user_id).present?
          query
        end

        def external_sources
          ::Ai::Governance::Session.sources.keys - INTERNAL_SOURCES
        end

        def source_values(names)
          ::Ai::Governance::Session.sources.values_at(*names)
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
