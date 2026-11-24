# frozen_string_literal: true

# Used to filter Work Items collections by set of params in Elasticsearch
#
# Arguments:
#   current_user    - ActiveRecord instance representing the currently logged-in user
#   resource_parent - ActiveRecord instance representing the parent of the work items (either a Project or a Group)
#   context         - GraphQL context object (an instance of GraphQL::Query::Context) that holds per-request metadata,
#                     such as the HTTP request, current user, etc.
#   params:
#     state                  - String with possible values of 'opened', 'closed', or 'all'
#     group_id               - ActiveRecord Group instance
#     project_id             - ActiveRecord Project instance
#     label_name             - Array of strings, can also accept wildcard values of "NONE" or "ANY"
#     sort                   - Symbol with possible values of :created_desc or :created_asc
#     confidential           - Boolean
#     author_username        - String
#     milestone_title:       - Array of strings (cannot be simultaneously used with milestone_wildcard_id)
#     milestone_wildcard_id: - String with possible values of  'none', 'any', 'upcoming', 'started'
#                              (cannot be simultaneously used with milestone_title)
#     assignee_usernames:    - Array of strings
#     assignee_wildcard_id:  - String with possible values of  'none', 'any'
#     weight:                - String containing integer representing work item's weight
#     weight_wildcard_id:    - String with possible values of  'none', 'any'
#     issue_types:           - Array of strings (one of WorkItems::TypesFramework::Provider.unfiltered_base_types)
#     work_item_type_ids:    - Array of integers representing work item type IDs (takes precedence over issue_types)
#     health_status_filter:  - String with possible values of 'on_track', 'needs_attention' and 'at_risk',
#                              can also accept wildcard values of "NONE" or "ANY"
#     due_after:             - Time object
#     due_before:            - Time object
#     created_after:         - Time object
#     created_before:        - Time object
#     updated_after:         - Time object
#     updated_before:        - Time object
#     closed_after:          - Time object
#     closed_before:         - Time object
#     iids                   - Array of strings of work items' iids
#     not                    - Hash with keys that can be negated
#     or                     - Hash with keys that can be combined using OR logic
#
module EE
  module Search
    module AdvancedFinders
      module WorkItemsFinder
        include ::Gitlab::Utils::StrongMemoize

        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        CONTROL_KEYS = [:sort].freeze

        # A hierarchy flag selects documents, so it is only safe to ignore at the value
        # Elasticsearch already applies: it always searches the whole group subtree.
        HIERARCHY_KEYS_MATCHING_ES = {
          include_ancestors: false,
          include_descendants: true,
          exclude_projects: false,
          exclude_group_work_items: false
        }.freeze
        ALLOWED_ES_FILTERS = [
          :label_name, :group_id, :project_id, :state, :confidential, :author_username,
          :milestone_title, :milestone_wildcard_id, :assignee_usernames, :assignee_wildcard_id, :not, :or,
          :weight, :weight_wildcard_id, :issue_types, :work_item_type_ids, :health_status_filter,
          :due_after, :due_before, :created_after, :created_before, :updated_after, :updated_before,
          :closed_after, :closed_before, :iids, :include_archived
        ].freeze
        NOT_FILTERS = [:author_username, :milestone_title, :assignee_usernames, :label_name, :weight,
          :weight_wildcard_id, :health_status_filter, :milestone_wildcard_id, :issue_types,
          :work_item_type_ids].freeze
        OR_FILTERS = [:assignee_usernames, :label_names].freeze

        SORT_KEYS = [
          :created_asc, :created_desc,
          :updated_asc, :updated_desc,
          :health_status_asc, :health_status_desc,
          :weight_asc, :weight_desc,
          :closed_at_asc, :closed_at_desc,
          :due_date_asc, :due_date_desc,
          :milestone_due_asc, :milestone_due_desc,
          :popularity_asc, :popularity_desc,
          :title_asc, :title_desc
        ].freeze

        FILTER_NONE = 'none'
        FILTER_ANY = 'any'
        FILTER_MILESTONE_UPCOMING = 'upcoming'
        FILTER_MILESTONE_STARTED = 'started'

        GLQL_SOURCE = 'GLQL'
        WORK_ITEMS_LIST_SOURCE = %w[getWorkItemsFullEE getWorkItemsSlimEE].freeze

        INDEX_NAME = ::Search::Elastic::References::WorkItem.index
        # Match-all query: returns every work item the filters allow.
        DEFAULT_QUERY = '*'

        attr_reader :current_user, :context, :params
        attr_accessor :resource_parent

        def execute
          work_item_query = ::Search::Elastic::WorkItemQueryBuilder.build(query: search_query, options: search_params)

          ::Search::Elastic::Relation.new(::WorkItem, work_item_query, es_search_options)
        end

        def es_search_options
          # This key is used by ES to find the correct shard
          # See Elastic::Latest::Routing for how it's used
          {
            index_name: INDEX_NAME,
            root_ancestor_ids: root_ancestor_ids
          }
        end

        def root_ancestor_ids
          [resource_parent.root_ancestor.id]
        end

        override :use_elasticsearch_finder?
        def use_elasticsearch_finder?
          allowed_request_source? &&
            use_elasticsearch? &&
            elasticsearch_enabled_for_namespace? &&
            elasticsearch_fields_supported?
        end

        # The logic for parent_param is copied from app/finders/issuable_finder.rb
        # Otherwise `find_all` fails in lib/gitlab/graphql/loaders/issuable_loader.rb
        def parent_param=(obj)
          self.resource_parent = obj
          params[parent_param] = resource_parent if resource_parent
        end

        def parent_param
          case resource_parent
          when Project
            :project_id
          when Group
            :group_id
          else
            raise "Unexpected parent: #{resource_parent.class}"
          end
        end

        private

        # A keyword searches across the title, description and iid fields;
        # absent or blank, it falls back to matching everything.
        def search_query
          params[:search].presence || DEFAULT_QUERY
        end

        def search_params
          base_params.merge(scope_param)
        end

        def base_params
          {
            sort: sort,
            state: params[:state],
            confidential: params[:confidential],
            work_item_type_ids: resolved_work_item_type_ids,
            not_work_item_type_ids: resolved_not_work_item_type_ids,
            current_user: current_user,
            # NOTE: when set to true is does a global search
            public_and_internal_projects: false,
            root_ancestor_ids: root_ancestor_ids,
            include_archived: params[:include_archived]
          }.merge(
            project_params,
            group_params,
            label_params,
            author_params,
            milestone_params,
            assignee_params,
            weight_params,
            health_status_params,
            dates_params,
            iids_params
          ).compact
        end

        def sort
          return 'created_desc' unless params[:sort].present?

          params[:sort].to_s
        end

        def project_scope?
          parent_param == :project_id
        end

        def group_scope?
          parent_param == :group_id
        end

        def group_params
          return {} unless group_scope?

          {
            search_level: 'group',
            group_ids: [resource_parent.id],
            group_id: resource_parent.id
          }
        end

        def project_params
          return {} unless project_scope?

          {
            search_level: 'project',
            project_ids: [resource_parent.id]
          }
        end

        def label_params
          {
            label_names: label_names(params[:label_name]),
            not_label_names: label_names(params.dig(:not, :label_name)),
            or_label_names: label_names(params.dig(:or, :label_names)),
            none_label_names: none_labels?(params[:label_name]),
            any_label_names: any_labels?(params[:label_name])
          }
        end

        def author_params
          {
            author_username: params[:author_username],
            not_author_username: params.dig(:not, :author_username)
          }
        end

        def milestone_params
          {
            milestone_title: params[:milestone_title],
            not_milestone_title: params.dig(:not, :milestone_title),
            none_milestones: none_milestones?,
            any_milestones: any_milestones?,
            milestone_state_filters: milestone_state_filters
          }
        end

        def assignee_params
          {
            assignee_ids: assignee_ids(params[:assignee_usernames]),
            not_assignee_ids: assignee_ids(params.dig(:not, :assignee_usernames)),
            or_assignee_ids: assignee_ids(params.dig(:or, :assignee_usernames)),
            none_assignees: none_assignees?,
            any_assignees: any_assignees?
          }
        end

        def weight_params
          {
            # NOTE: We receive weight as a string on the API level, but ES stores weight as integer
            weight: params[:weight]&.to_i,
            not_weight: params.dig(:not, :weight)&.to_i,
            none_weight: none_weight?,
            any_weight: any_weight?
          }
        end

        def health_status_params
          # NOTE: health_status_filter receives different input types:
          # - Positive queries (health = "value") receive a string
          # - Negation queries (health != "value") receive an array
          # Converting everything to array for consistent handling and ES query structure
          status_filter = Array(params[:health_status_filter])
          not_status_filter = Array(params.dig(:not, :health_status_filter))

          {
            health_status: health_status(status_filter),
            not_health_status: health_status(not_status_filter),
            none_health_status: none_health_status?(status_filter),
            any_health_status: any_health_status?(status_filter)
          }
        end

        def dates_params
          {
            due_after: params[:due_after],
            due_before: params[:due_before],
            created_after: params[:created_after],
            created_before: params[:created_before],
            updated_after: params[:updated_after],
            updated_before: params[:updated_before],
            closed_after: params[:closed_after],
            closed_before: params[:closed_before]
          }
        end

        def iids_params
          # NOTE: We receive iids as strings on the API level,
          # while iid is stored as integer in ES
          {
            iids: params[:iids]&.map(&:to_i)
          }
        end

        def scope_param
          if params[:project_id].present?
            { project_id: params[:project_id]&.id }
          else
            { group_id: params[:group_id]&.id }
          end
        end

        def any_milestones?
          params[:milestone_wildcard_id].to_s.downcase == FILTER_ANY
        end

        def none_milestones?
          params[:milestone_wildcard_id].to_s.downcase == FILTER_NONE
        end

        def resolved_work_item_type_ids
          return params[:work_item_type_ids] if params[:work_item_type_ids].present?

          type_ids_from(params[:issue_types])
        end

        def resolved_not_work_item_type_ids
          return params.dig(:not, :work_item_type_ids) if params.dig(:not, :work_item_type_ids).present?

          type_ids_from_negated(params.dig(:not, :issue_types))
        end

        def type_ids_from(type_names)
          return all_work_item_type_ids unless type_names.present?

          types_provider.by_base_types(Array(type_names)).map(&:id)
        end

        def type_ids_from_negated(type_names)
          return unless type_names.present?

          types_provider.by_base_types(Array(type_names)).map(&:id)
        end

        def all_work_item_type_ids
          types_provider.all.map(&:id)
        end

        def types_provider
          ::WorkItems::TypesFramework::Provider.new(resource_parent)
        end
        strong_memoize_attr :types_provider

        def upcoming_milestone?
          params[:milestone_wildcard_id].to_s.downcase == FILTER_MILESTONE_UPCOMING
        end

        def started_milestone?
          params[:milestone_wildcard_id].to_s.downcase == FILTER_MILESTONE_STARTED
        end

        def not_upcoming_milestone?
          params.dig(:not, :milestone_wildcard_id).to_s.downcase == FILTER_MILESTONE_UPCOMING
        end

        def not_started_milestone?
          params.dig(:not, :milestone_wildcard_id).to_s.downcase == FILTER_MILESTONE_STARTED
        end

        def milestone_state_filters
          filters = []

          filters << :upcoming if upcoming_milestone?
          filters << :started if started_milestone?
          filters << :not_upcoming if not_upcoming_milestone?
          filters << :not_started if not_started_milestone?

          filters.presence
        end

        def use_elasticsearch?
          ::Gitlab::CurrentSettings.elasticsearch_search?
        end

        def elasticsearch_enabled_for_namespace?
          resource_parent.use_elasticsearch?
        end

        def allowed_request_source?
          return false if ::Gitlab::CurrentSettings.advanced_search_indexing_paused?
          return true if glql_request? && ::Feature.enabled?(:glql_es_integration, current_user)
          return true if work_items_list_request? && ::Feature.enabled?(:work_items_list_es_integration, current_user)

          false
        end

        def glql_request?
          operation_name&.start_with?(GLQL_SOURCE)
        end

        def work_items_list_request?
          WORK_ITEMS_LIST_SOURCE.include?(operation_name)
        end

        def operation_name
          return unless request_params.present?

          request_params.fetch('operationName', nil)
        end

        def request_from_context
          context[:request]
        end

        def request_params
          request_from_context&.params
        end

        def elasticsearch_fields_supported?
          allowed_main_filters? &&
            allowed_not_filters? &&
            allowed_or_filters? &&
            allowed_sort?
        end

        def allowed_main_filters?
          filter_keys = params.keys - CONTROL_KEYS - ignorable_hierarchy_keys

          (filter_keys - allowed_es_filters).empty?
        end

        # Reaching this finder at all is gated by `glql_es_integration`, which
        # is on by default. Allowing `search` moves a query that would have
        # stayed on Postgres onto Elasticsearch, where matching and ranking
        # differ, so that step gets a flag of its own to roll out behind.
        def allowed_es_filters
          return ALLOWED_ES_FILTERS unless search_term_routing_enabled?

          ALLOWED_ES_FILTERS + [:search]
        end

        def search_term_routing_enabled?
          ::Feature.enabled?(:work_items_search_term_es_integration, current_user)
        end

        # At project scope the finder receives these flags unstripped; only PostgreSQL strips them.
        def ignorable_hierarchy_keys
          return HIERARCHY_KEYS_MATCHING_ES.keys if project_scope?

          HIERARCHY_KEYS_MATCHING_ES.filter_map do |key, es_value|
            key if params[key] == es_value || (key == :exclude_projects && only_group_types_requested?)
          end
        end

        # Elasticsearch already returns no project items for a group-only type (e.g. Epic).
        def only_group_types_requested?
          types = requested_types
          return false if types.blank?

          types.all?(&:only_for_group?)
        end

        # work_item_type_ids arrives as strings from GraphQL (GlobalID#model_id), while
        # the ids this compares against are integers, so it is excluded rather than
        # risking a silent type mismatch that picks the wrong ES authorization branch.
        def requested_types
          return unless params[:issue_types].present?

          types_provider.by_base_types(Array(params[:issue_types]))
        end

        def allowed_not_filters?
          return true unless params[:not].present?
          return false unless params[:not].is_a?(Hash)

          (params[:not].keys - NOT_FILTERS).empty?
        end

        def allowed_or_filters?
          return true unless params[:or].present?
          return false unless params[:or].is_a?(Hash)

          (params[:or].keys - OR_FILTERS).empty?
        end

        def allowed_sort?
          return true unless params[:sort].present?
          return false unless SORT_KEYS.include?(params[:sort].to_sym)

          # A sort key whose backing migration has not finished is not answerable by the index yet:
          # the field is either unmapped (400) or mapped but unpopulated for documents indexed
          # before the mapping change (200, ordered only by the tie-breaker). Returning false here
          # sends the request down the PostgreSQL path, which sorts correctly either way.
          ::Search::Elastic::Sorts::WorkItem.sort_available?(nil, sort)
        end
        strong_memoize_attr :allowed_sort?

        def none_assignees?
          params[:assignee_wildcard_id].to_s.downcase == FILTER_NONE
        end

        def any_assignees?
          params[:assignee_wildcard_id].to_s.downcase == FILTER_ANY
        end

        def assignee_ids(assignee_usernames)
          return unless assignee_usernames.present?

          ::User.by_username(assignee_usernames).pluck_primary_key
        end

        def any_labels?(names)
          Array(names).any? { |label| label.to_s.downcase == FILTER_ANY }
        end

        def none_labels?(names)
          Array(names).any? { |label| label.to_s.downcase == FILTER_NONE }
        end

        def label_names(names)
          return unless names.present?
          return if any_labels?(names) || none_labels?(names)

          names
        end

        def none_weight?
          params[:weight_wildcard_id].to_s.downcase == FILTER_NONE
        end

        def any_weight?
          params[:weight_wildcard_id].to_s.downcase == FILTER_ANY
        end

        def none_health_status?(statuses)
          statuses.any? { |status| status.to_s.downcase == FILTER_NONE }
        end

        def any_health_status?(statuses)
          statuses.any? { |status| status.to_s.downcase == FILTER_ANY }
        end

        def health_status(statuses)
          return unless statuses.present?
          return if none_health_status?(statuses) || any_health_status?(statuses)

          # NOTE: We receive health_status_filter as a 'string' on the API level,
          # but health_status is defined as a 'short' in ES mappings.
          statuses.filter_map { |status| ::WorkItem.health_statuses[status] }
        end
      end
    end
  end
end
