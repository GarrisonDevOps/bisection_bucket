# frozen_string_literal: true

module Analytics
  module Orbit
    class GrepService
      VERSION = '1.2.0'
      SUMMARY_TRUNCATE_LIMIT = 200
      MATCH_TRUNCATE_LIMIT = 500
      # Basic search returns one row per matching line, so fetch a wider window to find distinct files.
      BASIC_BLOB_WINDOW = 100
      SCOPE_DEFINITIONS = {
        'work_items' => 'WorkItem',
        'merge_requests' => 'MergeRequest',
        'blobs' => 'File',
        'commits' => 'Commit',
        'notes' => 'Note',
        'milestones' => 'Milestone',
        'users' => 'User',
        'projects' => 'Project',
        'groups' => 'Group',
        'branches' => 'Branch'
      }.freeze
      BRANCHES = 'branches'
      # Branches are searched in Gitaly, not by SearchService, so they are only searched when asked for.
      DEFAULT_SCOPES = (SCOPE_DEFINITIONS.keys - [BRANCHES]).freeze
      SCOPE_ALIASES = {
        'mr' => 'merge_requests', 'mrs' => 'merge_requests', 'merge_request' => 'merge_requests',
        'pr' => 'merge_requests', 'prs' => 'merge_requests',
        'issue' => 'work_items', 'issues' => 'work_items', 'work_item' => 'work_items',
        'epic' => 'work_items', 'epics' => 'work_items',
        'blob' => 'blobs', 'file' => 'blobs', 'files' => 'blobs', 'code' => 'blobs',
        'commit' => 'commits', 'note' => 'notes', 'comment' => 'notes', 'comments' => 'notes',
        'milestone' => 'milestones', 'user' => 'users', 'project' => 'projects', 'group' => 'groups',
        'branch' => BRANCHES
      }.freeze
      # Node type names, such as MergeRequest, name their scope too, so clients can send graph kinds as-is.
      NODE_SCOPES = SCOPE_DEFINITIONS.to_h { |scope, node| [node.downcase, scope] }.freeze
      PRELOAD_METHODS = {
        'work_items' => :with_api_entity_associations,
        'merge_requests' => :with_api_entity_associations,
        'milestones' => :with_api_entity_associations,
        'projects' => :with_api_entity_associations,
        'notes' => :with_web_entity_associations,
        'commits' => :with_api_commit_entity_associations
      }.freeze

      STATE_SCOPES = %w[work_items merge_requests milestones].freeze
      NOTEABLE_TOKEN_TYPES = { 'Issue' => 'WorkItem', 'MergeRequest' => 'MergeRequest' }.freeze

      AbusiveSearchError = Class.new(StandardError)

      # Maps aliases and node type names, in any case, to scope names. Unknown names pass through for the API to
      # reject.
      def self.normalize_scopes(names)
        names.map do |name|
          key = name.to_s.downcase
          SCOPE_ALIASES[key] || NODE_SCOPES[key] || key
        end.uniq
      end

      def initialize(target, current_user:, search:, limit:, per_scope:, scopes:, access_token: nil)
        @target = target
        @current_user = current_user
        @search = search
        @limit = limit
        @per_scope = per_scope
        @scopes = SCOPE_DEFINITIONS.keys & scopes
        @access_token = access_token
      end

      def execute
        verify_search!

        response = base_response
        @searches_run = 0
        @rate_limited = false
        @exception_tracked = false

        scopes.each do |scope|
          if response[:result_count] >= limit
            response[:truncated] = true
            response[:scopes] << { name: scope, status: 'skipped', reason: { code: 'limit_reached' } }
            next
          end

          append_scope(response, scope)
        end

        response
      end

      private

      attr_reader :target, :current_user, :search, :limit, :per_scope, :scopes, :access_token

      def base_response
        {
          version: VERSION,
          request: { search: search, limit: limit, per_scope: per_scope },
          target: { type: target_type, id: target.id, token: "#{target_type}[#{target.id}]",
                    full_path: target.full_path },
          scopes: [],
          results: [],
          result_count: 0,
          truncated: false
        }
      end

      def verify_search!
        return if scopes.empty?

        first_search = build_search(scopes.find { |scope| scope != BRANCHES } || DEFAULT_SCOPES.first, per_scope)
        return unless first_search.abuse_detected?

        raise AbusiveSearchError, first_search.abuse_messages.to_sentence.presence || 'search is not allowed'
      end

      def append_scope(response, scope)
        if @rate_limited
          response[:scopes] << failed_scope(scope, 'rate_limited')
          return
        end

        requested_count = [per_scope, limit - response[:result_count]].min
        return append_branches(response, requested_count) if scope == BRANCHES

        search_service = build_search(scope, requested_count + 1)

        unless search_service.scope == scope
          response[:scopes] << unavailable_scope(scope, 'not_available_for_search_type')
          return
        end

        if search_service.search_type_errors
          response[:scopes] << unavailable_scope(scope, 'search_type_error')
          return
        end

        if search_service.abuse_detected?
          response[:scopes] << failed_scope(scope, 'invalid_search')
          return
        end

        if charge_search_rate_limit!
          response[:scopes] << failed_scope(scope, 'rate_limited')
          return
        end

        window = fetch_window(scope, search_service, requested_count)
        search_service = build_search(scope, window) if window != requested_count + 1

        objects = search_service.search_objects(PRELOAD_METHODS[scope])
        if search_service.search_results.try(:failed?, scope)
          response[:scopes] << failed_scope(scope, 'search_failed')
          return
        end

        append_results(response, scope, objects.to_a, requested_count, search_service.search_type, window)
      rescue ActiveRecord::QueryCanceled # rubocop:disable Database/RescueQueryCanceled -- Preserve results from other scopes when one search times out
        response[:scopes] << failed_scope(scope, 'timeout')
      rescue StandardError => e
        track_exception_once(e, scope)
        response[:scopes] << failed_scope(scope, 'search_failed')
      end

      # Takes the checks of the REST branches endpoint: read_code on the project and read_branch for a token.
      # Names come from Repositories::BranchNamesFinder, as for the GraphQL branchNames field.
      # A group target, or a project the caller cannot read code in, reports the scope as unavailable.
      def append_branches(response, requested_count)
        unless target.is_a?(Project) && branches_readable?
          response[:scopes] << unavailable_scope(BRANCHES, 'not_available_for_target')
          return
        end

        if charge_search_rate_limit!
          response[:scopes] << failed_scope(BRANCHES, 'rate_limited')
          return
        end

        names = ::Repositories::BranchNamesFinder.new(
          target.repository, search: branch_pattern, offset: 0, limit: requested_count + 1
        ).execute.to_a
        append_results(response, BRANCHES, names, requested_count, 'basic', requested_count + 1)
      end

      # Branch names come from the Redis set cache, which only reads Gitaly on a miss. The search becomes a
      # case-insensitive glob, with words joined by `*` so `fix login` matches `fix-login`.
      def branch_pattern
        glob = search.split.map do |word|
          word.chars.map do |char|
            next "[#{char.downcase}#{char.upcase}]" if char.match?(/[a-z]/i)

            '*?[]\\'.include?(char) ? "\\#{char}" : char
          end.join
        end.join('*')

        "*#{glob}*"
      end

      def branches_readable?
        return false unless Ability.allowed?(current_user, :read_code, target)
        return true unless access_token

        ::Authz::Tokens::AuthorizeGranularScopesService.new(
          boundaries: ::Authz::Boundary.for(target), permissions: :read_branch, token: access_token
        ).execute.success?
      end

      # The API charges search_rate_limit for the first search, so each further search costs one more unit.
      # Returns true when this search is throttled.
      def charge_search_rate_limit!
        @searches_run += 1
        return false if @searches_run == 1

        @rate_limited = ::Gitlab::ApplicationRateLimiter.throttled?(
          :search_rate_limit,
          scope: { user: current_user },
          users_allowlist: ::Gitlab::CurrentSettings.current_application_settings.search_rate_limit_allowlist
        )
      end

      # One backend outage fails every scope, so report a single exception per request.
      def track_exception_once(exception, scope)
        return if @exception_tracked

        @exception_tracked = true
        ::Gitlab::ErrorTracking.track_exception(exception, scope: scope)
      end

      def fetch_window(scope, search_service, requested_count)
        return requested_count + 1 unless scope == 'blobs' && search_service.search_type == 'basic'

        BASIC_BLOB_WINDOW
      end

      # A full window may hide more files, so it also counts as more results.
      def append_results(response, scope, objects, requested_count, search_type, window)
        window_full = window > requested_count + 1 && objects.size >= window
        objects = dedupe(scope, objects, search_type)
        has_more = objects.size > requested_count || window_full
        results = objects.first(requested_count).map { |object| build_result(scope, object, search_type) }

        response[:results].concat(results)
        response[:scopes] << {
          name: scope, status: 'ok', backend: search_type, result_count: results.size,
          pagination: { has_more: has_more }
        }
        response[:result_count] += results.size
        response[:truncated] ||= has_more
      end

      def unavailable_scope(scope, code)
        { name: scope, status: 'unavailable', reason: { code: code } }
      end

      def failed_scope(scope, code)
        { name: scope, status: 'error', reason: { code: code } }
      end

      def build_search(scope, per_page)
        params = {
          search: search,
          scope: scope,
          per_page: per_page,
          source: 'api',
          skip_legacy_scope_conversion: true,
          organization_id: target.organization_id
        }
        params[target.is_a?(Project) ? :project_id : :group_id] = target.id
        ::SearchService.new(current_user, params)
      end

      # Basic search returns one row per matching line, so keep the first match for each file.
      def dedupe(scope, objects, search_type)
        return objects unless scope == 'blobs' && search_type == 'basic'

        objects.uniq { |blob| [blob_project_id(blob), blob.path] }
      end

      def build_result(scope, object, search_type)
        result = {
          scope: scope,
          type: SCOPE_DEFINITIONS.fetch(scope),
          id: %w[blobs branches].include?(scope) ? nil : object.id,
          token: token_for(scope, object),
          reference: reference_for(scope, object, search_type),
          text: text_for(scope, object)
        }
        matches = matches_for(scope, object)
        result[:matches] = matches if matches
        result[:state] = object.state if STATE_SCOPES.include?(scope)
        result
      end

      def token_for(scope, object)
        return "#{target.full_path}@#{object}" if scope == BRANCHES
        return "#{object.project.full_path}@#{object.id}" if scope == 'commits'
        return if scope == 'blobs'

        "#{SCOPE_DEFINITIONS.fetch(scope)}[#{object.id}]"
      end

      def reference_for(scope, object, search_type)
        case scope
        when 'blobs'
          {
            project_id: blob_project_id(object), project_path: object.project.full_path, path: object.path,
            branch: blob_branch(object, search_type), commit_sha: blob_commit_sha(object, search_type)
          }
        when 'commits'
          { project_id: object.project.id, project_path: object.project.full_path, sha: object.id }
        when BRANCHES
          { project_id: target.id, project_path: target.full_path, name: object }
        when 'notes'
          { id: object.id, noteable: noteable_token(object), noteable_reference: noteable_reference(object) }.compact
        when 'merge_requests'
          { id: object.id, iid: object.iid, project_path: object.project.full_path }
        when 'work_items'
          work_item_reference(object)
        else
          { id: object.id }
        end
      end

      def text_for(scope, object)
        value = case scope
                when 'work_items', 'merge_requests', 'milestones', 'commits'
                  object.title
                when 'blobs'
                  object.path
                when BRANCHES
                  object
                when 'notes'
                  object.note
                when 'users'
                  [object.username, object.name].compact.join(' ')
                else
                  object.full_path
                end

        value.to_s.squish.truncate(SUMMARY_TRUNCATE_LIMIT)
      end

      def matches_for(scope, object)
        return unless scope == 'blobs' && object.respond_to?(:startline) && object.respond_to?(:data)
        return unless object.startline

        text = object.data.to_s
        [{
          start_line: object.startline,
          end_line: object.startline + text.lines.size - 1,
          text: text.rstrip.truncate(MATCH_TRUNCATE_LIMIT)
        }]
      end

      # Advanced Search sets ref to a commit SHA, so only Basic search ref is a branch name.
      def blob_branch(object, search_type)
        return object.ref if search_type == 'basic' && object.respond_to?(:ref) && object.ref.present?

        object.project.default_branch
      end

      def blob_commit_sha(object, search_type)
        object.ref if search_type == 'advanced' && object.respond_to?(:ref)
      end

      def work_item_reference(work_item)
        reference = { id: work_item.id, iid: work_item.iid }
        return reference.merge(project_path: work_item.project.full_path) if work_item.project

        reference.merge(namespace_path: work_item.namespace.full_path)
      end

      def noteable_token(note)
        type = NOTEABLE_TOKEN_TYPES[note.noteable_type]
        "#{type}[#{note.noteable_id}]" if type
      end

      def noteable_reference(note)
        if note.for_commit?
          "#{note.project.full_path}#{Commit.reference_prefix}#{note.commit_id}"
        elsif NOTEABLE_TOKEN_TYPES.key?(note.noteable_type)
          note.noteable&.to_reference(full: true)
        end
      end

      def blob_project_id(object)
        return object.project_id if object.respond_to?(:project_id) && object.project_id

        object.project.id
      end

      def target_type
        target.is_a?(Project) ? 'Project' : 'Group'
      end
    end
  end
end
