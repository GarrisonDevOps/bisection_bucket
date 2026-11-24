# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      # Shared resolution logic for Duo Agent Platform session artifacts.
      # Concrete resolvers expose their own filter argument set: the group
      # resolver also offers `project_path`, while the project resolver omits
      # it because the project is already fixed by the parent object.
      class BaseSessionArtifactsResolver < ::Resolvers::BaseResolver
        type ::Types::Ai::DuoWorkflows::SessionArtifactType.connection_type, null: true

        AGENT_TYPE_FILTER_BY_AGENT_CLASS = { internal_dap: :none, external: :any }.freeze

        # Every listing reads at most this span, so the ClickHouse dedup and the count never grow
        # with a namespace's whole history. A lookup by `workflow_id` matches one row and needs no window.
        MAX_WINDOW = 180.days

        argument :workflow_definition, GraphQL::Types::String,
          required: false,
          description: 'Filter by workflow definition.'

        argument :agent_class, ::Types::Ai::Governance::AgentClassEnum,
          required: false,
          description: 'Filter sessions by agent class. Defaults to all agent classes.'

        argument :workflow_created_after, ::Types::TimeType,
          required: false,
          description: 'Return sessions created after the timestamp. Defaults to 180 days before ' \
            '`workflowCreatedBefore`, or before now, and is moved up to that bound when it is earlier.'

        argument :workflow_created_before, ::Types::TimeType,
          required: false,
          description: 'Return sessions created before the timestamp. Defaults to now.'

        argument :not, ::Types::Ai::DuoWorkflows::SessionArtifactNegatedFilterInput,
          required: false,
          description: 'Negated filter conditions.'

        argument :workflow_id, ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: false,
          description: 'Filter to a single session by its workflow (session) global ID. ' \
            'No default time window applies when given.'

        argument :triggered_by_user_id, ::Types::GlobalIDType[::User],
          required: false,
          description: 'Filter to sessions triggered by the user with the given global ID.'

        def resolve(**args)
          args[:workflow_id] = args[:workflow_id]&.model_id&.to_i
          args[:triggered_by_user_id] = args[:triggered_by_user_id]&.model_id&.to_i
          args[:not] = prepare_not_args(args[:not])

          if args[:workflow_created_after] && args[:workflow_created_before] &&
              args[:workflow_created_after] >= args[:workflow_created_before]
            raise Gitlab::Graphql::Errors::ArgumentError,
              'workflowCreatedAfter must be before workflowCreatedBefore'
          end

          args[:workflow_created_after] = bounded_workflow_created_after(args)

          # ClickHouse returns a `QueryBuilder` handled by the connection type. The
          # PostgreSQL path returns an in-operator-optimized relation whose ordering
          # lives inside a recursive CTE, so it must use offset (not keyset)
          # pagination: the keyset connection cannot read the order off the
          # wrapped relation and would silently fall back to ordering by `id`.
          if ::Gitlab::ClickHouse.globally_enabled_for_analytics?
            session_artifacts_finder(args).execute
          else
            reject_unsupported_filters!(args)
            offset_pagination(session_artifacts_finder(args).execute)
          end
        end

        private

        def session_artifacts_finder(args)
          ::Ai::DuoWorkflows::SessionArtifactsFinder.new(
            current_user: current_user,
            namespace: resolver_namespace,
            params: finder_params(args)
          )
        end

        # Subclasses override with filters the PostgreSQL finder cannot serve:
        # the finder silently ignores params it has no filter for, so an
        # unguarded ClickHouse-only filter would return unfiltered results.
        def unsupported_pg_args
          []
        end

        def finder_params(_args)
          raise NotImplementedError
        end

        # The floor starts from now at the latest, so a future `workflowCreatedBefore` keeps recent sessions.
        #
        # @param args [Hash] resolver arguments
        # @return [Time, nil] start of the window, or the caller's value for a `workflowId` lookup
        def bounded_workflow_created_after(args)
          return args[:workflow_created_after] if args[:workflow_id]

          floor = [args[:workflow_created_before], Time.current].compact.min - MAX_WINDOW
          [args[:workflow_created_after], floor].compact.max
        end

        def agent_type_filter(agent_class)
          AGENT_TYPE_FILTER_BY_AGENT_CLASS[agent_class]
        end

        # On a project-scoped field the resolver `object` is the project; scope
        # to its project_namespace so the PostgreSQL (in-operator over the
        # namespace hierarchy) and ClickHouse (`traversal_path`) finders both
        # resolve to the single project. On a group-scoped field the object is
        # already the group namespace and is used as-is.
        def resolver_namespace
          object.respond_to?(:project_namespace) ? object.project_namespace : object
        end

        def reject_unsupported_filters!(args)
          used = unsupported_pg_args.select { |arg| args[arg].present? }
          return if used.empty?

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Filtering by #{used.join(', ')} requires ClickHouse to be enabled for analytics."
        end

        # Unwraps the negated user global ID and renames it to the `user_id`
        # column the finders filter on.
        #
        # The key is only written when it was actually provided: assigning
        # unconditionally would add a `nil` entry, making an otherwise empty
        # `not: {}` argument `present?` and tripping `reject_unsupported_filters!`
        # on the PostgreSQL path.
        def prepare_not_args(not_arg)
          not_arg&.to_h&.tap do |not_hash|
            triggered_by_user_id = not_hash.delete(:triggered_by_user_id)
            not_hash[:user_id] = triggered_by_user_id.model_id.to_i if triggered_by_user_id
          end
        end
      end
    end
  end
end
