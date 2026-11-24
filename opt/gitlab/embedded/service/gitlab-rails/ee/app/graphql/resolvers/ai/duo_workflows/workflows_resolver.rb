# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::ResolvesIds
        include LooksAhead
        include ::Gitlab::InternalEventsTracking

        type Types::Ai::DuoWorkflows::WorkflowType, null: false

        argument :project_path, GraphQL::Types::ID,
          required: false,
          description: 'Full path of the project that contains the flows.'

        argument :project_id, Types::GlobalIDType[::Project],
          required: false,
          description: 'Global ID of the project that contains the flows.'

        validates mutually_exclusive: [:project_path, :project_id]

        argument :merge_request_iid, GraphQL::Types::String,
          required: false,
          description: 'IID of a merge request to filter flows by. ' \
            'Requires `projectId` or `projectPath` outside a project.'

        argument :type, GraphQL::Types::String,
          required: false,
          description: 'Type of flow to filter by (for example, software_development or foundational_chat_agents).'

        argument :exclude_types, [GraphQL::Types::String],
          required: false,
          description: 'Types of flows to exclude (for example, ["software_development", "chat"]).'

        argument :exclude_source_types, [Types::Ai::DuoWorkflows::WorkflowSourceTypeEnum],
          required: false,
          experiment: { milestone: '19.5' },
          description: 'Source types to exclude. Sessions with no recorded source type are never excluded.'

        argument :exclude_created_interactive_cli_sessions, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          experiment: { milestone: '19.6' },
          description: 'Exclude `CREATED` sessions from the `DUO_CLI_INTERACTIVE` and `DUO_CLI_ACP` sources. ' \
            'Explicit `ids` and `workflowId` lookups bypass this filter.'

        argument :sort, Types::Ai::DuoWorkflows::WorkflowSortEnum,
          description: 'Sort flows by the criteria.',
          required: false,
          default_value: :created_desc

        argument :environment, Types::Ai::DuoWorkflows::WorkflowEnvironmentEnum,
          description: 'Environment, for example, IDE or web.',
          required: false

        argument :workflow_id, Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: false,
          description: 'Flow ID to filter by.'

        argument :ids, [Types::GlobalIDType[::Ai::DuoWorkflows::Workflow]],
          required: false,
          description: 'Filter flows by a list of IDs.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Flow title or goal to search for. ' \
            'When the `duo_workflow_project_search_guard` feature flag is enabled, words shorter than ' \
            '3 characters are ignored and at most 10 words are matched. If every word is shorter than ' \
            '3 characters, the whole term must match the title or goal exactly. Searches also only ' \
            'match sessions created in the last 30 days, unless the search is only session IDs. When ' \
            'disabled, every word is matched against all sessions.'

        argument :status_group, Types::Ai::DuoWorkflows::WorkflowStatusGroupEnum,
          required: false,
          description: 'Status group to filter flow sessions by.'

        argument :statuses, [Types::Ai::DuoWorkflows::WorkflowStatusEnum],
          required: false,
          description: 'Exact statuses to filter flow sessions by. Cannot be combined with statusGroup.'

        argument :updated_after, GraphQL::Types::ISO8601DateTime,
          required: false,
          description: 'Filters flows updated after a given date.'

        argument :work_item_iid, GraphQL::Types::String,
          required: false,
          description: 'IID of a work item to filter flows by. Requires `projectId` or `projectPath` outside a project.'

        validates mutually_exclusive: [:status_group, :statuses]

        before_connection_authorization do |workflows, current_user|
          ::Ai::DuoWorkflows::WorkflowPolicyPreloader.new(workflows, current_user).execute
        end

        def resolve_with_lookahead(**args)
          return [] unless current_user

          # Return empty array if type and exclude filters conflict
          return [] if conflicting_type_filters?(args)

          validate_iid_filter!(args, :work_item_iid, 'workItemIid')
          validate_iid_filter!(args, :merge_request_iid, 'mergeRequestIid')

          return resolve_single_workflow(args[:workflow_id]) if args[:workflow_id].present?

          # Treat ids: null as an omitted filter, but keep ids: [] as an explicit lookup.
          ids_arg = args.delete(:ids)
          args[:ids] = resolve_ids(ids_arg) if ids_arg

          finder = ::Ai::DuoWorkflows::WorkflowsFinder.new(
            source: object,
            current_user: current_user,
            project_path: args[:project_path],
            project_id: args[:project_id]&.model_id,
            merge_request_iid: args[:merge_request_iid],
            type: args[:type],
            exclude_types: args[:exclude_types],
            exclude_source_types: args[:exclude_source_types],
            environment: args[:environment],
            sort: args[:sort],
            search: args[:search],
            guard_search: true,
            status_group: args[:status_group],
            statuses: args[:statuses],
            updated_after: args[:updated_after],
            work_item_iid: args[:work_item_iid],
            ids: args[:ids]
          )

          handle_session_search!(args, finder) if args[:search].present?

          workflows = finder.results

          if args[:exclude_created_interactive_cli_sessions] && !args[:ids]
            workflows = workflows.without_empty_cli_sessions
          end

          offset_pagination(apply_lookahead(workflows.with_preloaded_associations))
        end

        private

        # URL helpers build `namespace_id` from `project.namespace.full_path`. The work item
        # and merge request policies reuse the ProjectPolicy cached for the workflow's project,
        # so `project_feature` goes on that instance. Group-level session URLs use the root
        # group's route, which `WorkflowPolicyPreloader` batches, so only `project` is listed
        # for `web_url` / `web_path`.
        def preloads
          {
            project: { project: [:route, { namespace: :route }] },
            web_url: [{ project: [:route, { namespace: :route }] }],
            web_path: [{ project: [:route, { namespace: :route }] }],
            work_item: [
              { work_item: [:author, { namespace: { project: { namespace: :route } } },
                { project: [:project_namespace, { namespace: :route }] }] },
              { project: :project_feature }
            ],
            merge_request: [
              { merge_request: [:author, { target_project: [:project_namespace, { namespace: :route }] }] },
              { project: :project_feature }
            ]
          }
        end

        # IIDs are only unique within a project, so outside a project page one must be given.
        def validate_iid_filter!(args, key, name)
          iid = args[key]
          return if iid.blank?

          raise Gitlab::Graphql::Errors::ArgumentError, "#{name} must be a number." unless iid.match?(/\A\d+\z/)

          return if object.is_a?(::Project) || args[:project_id] || args[:project_path].present?

          raise Gitlab::Graphql::Errors::ArgumentError, "#{name} requires projectId or projectPath."
        end

        def conflicting_type_filters?(args)
          exclude_types = args[:exclude_types] || []
          return false unless args[:type].present? && exclude_types.present?

          exclude_types.include?(args[:type])
        end

        # Fires an internal event and a structured log line for every session search.
        # Logs word count and scope so we can measure usage without capturing the
        # raw search term (which may contain sensitive goal text).
        def track_session_search(search, project)
          scope = project ? 'project' : 'user'
          guarded = ::Feature.enabled?(:duo_workflow_project_search_guard, current_user)
          word_count = ::Ai::DuoWorkflows::WorkflowsFinder.search_term_count(search, guarded: guarded)

          track_internal_event(
            'search_duo_workflow_sessions',
            user: current_user,
            project: project,
            namespace: project&.namespace,
            additional_properties: {
              label: scope,
              value: word_count
            }
          )

          Gitlab::AppLogger.info(
            message: 'duo_workflow_session_search',
            Labkit::Fields::GL_USER_ID => current_user.id,
            Labkit::Fields::GL_PROJECT_ID => project&.id,
            scope: scope,
            word_count: word_count,
            char_count: search.length
          )
        end

        # Throttles project-scoped search requests when the guard flag is on.
        # `project` is nil for searches that are not scoped to a project, so no project-level limit applies.
        def check_project_search_rate_limit!(project)
          return unless project
          return unless ::Feature.enabled?(:duo_workflow_project_search_guard, current_user)

          if ::Gitlab::ApplicationRateLimiter.throttled?(:duo_workflow_project_search,
            scope: { user: current_user, project: project })
            raise_resource_not_available_error!('Too many search requests. Please wait before searching again.')
          end
        end

        # The finder returns no sessions for a project the user cannot use, so skip throttling and tracking.
        # Reuses the finder's project so a project-scoped search looks it up once.
        def handle_session_search!(args, finder)
          project = object.is_a?(::Project) ? object : finder.scoped_project
          project_scoped = object.is_a?(::Project) || args[:project_id].present? || args[:project_path].present?
          return if project_scoped && !Ability.allowed?(current_user, :duo_workflow, project)

          check_project_search_rate_limit!(project)
          track_session_search(args[:search], project)
        end

        def resolve_single_workflow(workflow_id)
          Gitlab::Graphql::Lazy.with_value(find_object(id: workflow_id)) do |workflow|
            if workflow.nil? || !Ability.allowed?(current_user, :read_duo_workflow, workflow)
              if ::Gitlab::ApplicationRateLimiter.throttled?(:duo_workflow_unauthorized_access,
                scope: { user: current_user, duo_workflow: workflow_id.model_id })
                raise_resource_not_available_error!('Too many requests.')
              end

              raise_resource_not_available_error!(
                'Workflow not found',
                { code: ::Gitlab::Graphql::Ai::ErrorCodes::WORKFLOW_NOT_FOUND }
              )
            else
              ::Ai::DuoWorkflows::Workflow.id_in([workflow.id])
            end
          end
        end

        def find_object(id:)
          GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
