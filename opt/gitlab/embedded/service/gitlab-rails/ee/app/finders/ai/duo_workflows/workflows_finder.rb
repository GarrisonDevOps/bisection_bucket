# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowsFinder
      include ::Gitlab::Utils::StrongMemoize

      UnknownOptionError = Class.new(StandardError)

      # Identifies possible IDs in a search term. A digit run only counts as
      # an ID when it is a standalone token: preceded by start-of-string,
      # whitespace, or `#`, and followed by whitespace or end-of-string.
      # Digits embedded inside URLs or other identifiers are NOT treated as IDs.
      #   soft devel 123                          -> 123
      #   soft devel #123                         -> 123
      #   #123 soft devel                         -> 123
      #   soft devel v1                           -> ""
      #   soft devel v12 #123 456                 -> 123, 456
      #   http://example.com/-/pipelines/1154     -> ""
      SEARCH_IDS_PATTERN = /(?<=^|\s|#)\d+(?=\s|$)/

      # Removes possible IDs (and a leading `#` if present) from a search term,
      # using the same standalone-token rule as SEARCH_IDS_PATTERN.
      #   soft devel 123                          -> soft devel
      #   soft devel #123                         -> soft devel
      #   #123 soft devel                         -> soft devel
      #   soft devel v1                           -> soft devel v1
      #   soft devel v12 #123 456                 -> soft devel v12
      #   http://example.com/-/pipelines/1154     -> http://example.com/-/pipelines/1154
      SEARCH_IDS_SANITIZER_PATTERN = /(?:^|\s)#?\d+(?=\s|$)/

      # Maximum number of words passed to fuzzy_search when the guard is active.
      # Each word adds one ILIKE clause; capping prevents unbounded query growth.
      MAX_SEARCH_WORDS = 10

      # When the guard is active, restrict the ILIKE scan to sessions created
      # within this window. The existing (project_id, created_at DESC) index
      # turns the full-table scan into a bounded range scan.
      SEARCH_RECENCY_WINDOW_DAYS = 30

      # A quoted phrase, matched the same way fuzzy_search matches it, or a single word.
      SEARCH_TERM_PATTERN = /#{::Gitlab::SQL::Pattern::REGEX_QUOTED_TERM}|\S+/

      # Search terms after ID extraction, and the word cap when `capped`. A quoted phrase stays
      # one term, and terms keep the order they were typed so the cap drops trailing ones.
      def self.search_terms(term, capped: true)
        # Squish like fuzzy_search does, so Unicode spaces split words here too and can't dodge the cap.
        terms = term.squish.gsub(SEARCH_IDS_SANITIZER_PATTERN, '').scan(SEARCH_TERM_PATTERN)
        return terms unless capped

        # Only terms of 3+ chars become an ILIKE, so cap those. When all are short,
        # fuzzy_search matches the whole term once, so keep them as they are.
        # Like fuzzy_search, only strip the quotes of a balanced phrase, so `"ab` counts as 3 characters.
        matchable = terms.select do |t|
          phrase = t.match?(::Gitlab::SQL::Pattern::REGEX_QUOTED_TERM) ? t[1..-2] : t
          phrase.length >= ::Gitlab::SQL::Pattern::MIN_CHARS_FOR_PARTIAL_MATCHING
        end
        matchable.any? ? matchable.first(MAX_SEARCH_WORDS) : terms
      end

      # Terms the search actually matches on. With the guard on, fuzzy_search drops words under
      # 3 chars, or matches the whole term once when every word is short.
      def self.search_term_count(term, guarded:)
        terms = search_terms(term, capped: guarded)
        return 0 if terms.empty?

        matched = ::Ai::DuoWorkflows::Workflow.select_fuzzy_terms(terms.join(' '), use_minimum_char_limit: guarded)
        matched.empty? ? 1 : matched.size
      end

      class SortingCriteria
        SORTABLE_DIRECTIONS = %w[asc desc].freeze

        attr_reader :field, :direction

        def self.parse(criteria)
          *fields, direction = criteria.to_s.strip.downcase.split('_')

          unless direction.in?(SORTABLE_DIRECTIONS)
            fields << direction
            direction = SORTABLE_DIRECTIONS.first
          end

          new(fields.join("_"), direction)
        end

        def initialize(field, direction)
          @field = field
          @direction = direction
        end

        def to_s
          "#{field}_#{direction}"
        end
      end

      def initialize(options = {})
        @options = options.reverse_merge(default_options)
      end

      def results
        self.query = base_query

        options.each do |key, value|
          method_name = "resolve_#{key}"
          # rubocop:disable GitlabSecurity/PublicSend -- Method names don't come from user input
          self.query = public_send(method_name, value) if respond_to?(method_name) && resolvable?(value)
          # rubocop:enable GitlabSecurity/PublicSend
        end

        query
      end

      # The project named by `project_path` or `project_id`. Memoized so the resolver can reuse it.
      def scoped_project
        if option?(:project_path) && option?(:project_id)
          raise ArgumentError, 'project_path and project_id cannot be used together'
        end

        if option?(:project_path)
          ::Project.find_by_full_path(option(:project_path))
        elsif option?(:project_id)
          ::Project.find_by_id(option(:project_id))
        end
      end
      strong_memoize_attr :scoped_project

      def base_query
        workflows = ::Ai::DuoWorkflows::Workflow

        current_user = option(:current_user)
        source = option(:source)

        return workflows.none unless current_user

        if source.is_a?(::Project)
          return workflows.none unless Ability.allowed?(current_user, :duo_workflow, source)

          workflows.for_project(source).from_pipeline
            .without_other_users_private_sessions(current_user.id)
        elsif option?(:project_path)
          return workflows.none unless Ability.allowed?(current_user, :duo_workflow, scoped_project)

          workflows
            .for_user(current_user.id)
            .for_project(scoped_project)
        else
          workflows.for_user(current_user.id)
        end
      end

      def default_options
        {
          sort: "created_desc"
        }
      end

      def resolve_type(type)
        raise ArgumentError, "type must be a string, got #{type.class}" unless type.is_a?(String)

        case type
        when 'non_foundational_chat_agents'
          query.without_foundational_chat_agents
        when 'foundational_chat_agents'
          query.with_workflow_definition(::Ai::FoundationalChatAgent.workflow_definitions)
        else
          query.with_workflow_definition(type)
        end
      end

      def resolve_exclude_types(exclude_types)
        query.without_workflow_definition(exclude_types)
      end

      def resolve_exclude_source_types(exclude_source_types)
        query.without_source_types(exclude_source_types)
      end

      def resolve_environment(environment)
        query.with_environment(environment)
      end

      def resolve_sort(sort)
        criteria = SortingCriteria.parse(sort)

        case criteria.field
        when "status"
          query.order_by_status(criteria.direction)
        when "id"
          query.order_by(criteria.to_s)
        else
          query.order_by_with_id_tie_breaker(criteria.to_s, criteria.direction)
        end
      end

      def resolve_search(term)
        possible_ids = term.scan(SEARCH_IDS_PATTERN).map(&:to_i)
        term_without_ids = term.gsub(SEARCH_IDS_SANITIZER_PATTERN, '').strip

        scope = query

        if term_without_ids.present?
          if project_scoped_search_guard_enabled?
            # Words under 3 chars are dropped unless all are short, which falls back to an exact-match ILIKE.
            capped_term = self.class.search_terms(term_without_ids).join(' ')
            scope = scope.fuzzy_search(capped_term, [:workflow_definition, :goal])

            # Restrict the scan to recent sessions so the planner can use the existing
            # (project_id, created_at DESC) or (user_id, created_at DESC) index instead of
            # reading every session in the project or of the user.
            scope = scope.created_after(SEARCH_RECENCY_WINDOW_DAYS.days.ago)
          else
            # Legacy path: allow short tokens like `v1` at the cost of a full scan.
            scope = scope.fuzzy_search(term_without_ids, [:workflow_definition, :goal], use_minimum_char_limit: false)
          end
        end

        scope = scope.id_in(possible_ids) if possible_ids.any?

        scope
      end

      def resolve_status_group(status_group)
        query.in_status_group(status_group)
      end

      def resolve_statuses(statuses)
        query.in_statuses(statuses)
      end

      def resolve_ids(ids)
        query.id_in(ids)
      end

      def resolve_project_id(_project_id)
        return query if option(:source).is_a?(::Project)

        project = scoped_project
        current_user = option(:current_user)

        return query.none unless project && Ability.allowed?(current_user, :duo_workflow, project)

        query.for_project(project)
      end

      def resolve_work_item_iid(iid)
        project_id = iid_lookup_project_id
        return query.none unless project_id

        query.for_project_and_work_item_iid(project_id, iid)
      end

      def resolve_merge_request_iid(iid)
        project_id = iid_lookup_project_id
        return query.none unless project_id

        query.for_project_and_merge_request_iid(project_id, iid)
      end

      def resolve_updated_after(updated_after)
        query.updated_after(updated_after)
      end

      def resolve_created_after(created_after)
        query.created_after(created_after)
      end

      def resolve_created_before(created_before)
        query.created_before(created_before)
      end

      def resolve_flow_triggers(flow_triggers)
        query.for_flow_triggers(flow_triggers)
      end

      private

      attr_accessor :query

      attr_reader :options

      def resolvable?(value)
        case value
        when NilClass
          false
        when String
          value.present?
        when Array
          # Pass arrays through even when empty: the underlying scopes already
          # do the right thing (`id_in([])` matches nothing, `without_workflow_definition([])`
          # is a no-op), and skipping `id_in([])` would silently fall back to the
          # unfiltered relation.
          true
        else
          true
        end
      end

      def option(name)
        options.fetch(name) { raise UnknownOptionError, name }
      end

      def option?(name)
        resolvable?(options[name])
      end

      # Only the session list sets `guard_search`, so other finder callers keep their results.
      def project_scoped_search_guard_enabled?
        options[:guard_search].present? &&
          ::Feature.enabled?(:duo_workflow_project_search_guard, option(:current_user))
      end

      # The project an IID filter is looked up in, since IIDs are only unique within a project.
      def iid_lookup_project_id
        source = option(:source)
        return source.id if source.is_a?(::Project)
        return options[:project_id] if option?(:project_id)

        scoped_project&.id if option?(:project_path)
      end
    end
  end
end
