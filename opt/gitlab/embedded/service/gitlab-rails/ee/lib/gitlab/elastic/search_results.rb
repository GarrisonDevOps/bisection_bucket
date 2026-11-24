# frozen_string_literal: true

module Gitlab
  module Elastic
    class SearchResults
      include ActionView::Helpers::NumberHelper
      include Gitlab::Utils::StrongMemoize
      include ::Search::ScopeHandlers::Delegation

      ELASTIC_COUNT_LIMIT = 10000
      DEFAULT_PER_PAGE = Gitlab::SearchResults::DEFAULT_PER_PAGE
      DEFAULT_NUM_CONTEXT_LINES = 2
      MAX_NUM_CONTEXT_LINES = 20

      # Epic type ID from system-defined work item types
      # This is a temporary constant until work_items_types table is fully removed
      # and replaced with in-memory type definitions.
      # See: https://gitlab.com/gitlab-org/gitlab/-/blob/f427bc9e0dea05bfe7c820077d482d2ea8c1a610/app/models/work_items/type.rb#L42
      EPIC_TYPE_ID = 8

      attr_reader :current_user, :query, :public_and_internal_projects, :order_by, :sort, :filters, :root_ancestor_ids

      def self.parse_search_result(result, container, options = {})
        ref = extract_ref_from_result(result['_source'])
        path = extract_path_from_result(result['_source'])
        basename = File.join(File.dirname(path), File.basename(path, '.*'))
        content = extract_content_from_result(result['_source'])
        group_id = result['_source']['group_id']&.to_i
        num_context_lines = options[:num_context_lines]&.clamp(0, MAX_NUM_CONTEXT_LINES) || DEFAULT_NUM_CONTEXT_LINES

        if group_level_result?(result['_source'], container)
          group = container
          group_level_blob = true
        else
          project = container
          group = container.group
          project_id = result['_source']['project_id'].to_i
        end

        total_lines = content.lines.size

        highlight_content = get_highlight_content(result)

        found_line_number = 0
        highlight_found = false

        highlight_content.each_line.each_with_index do |line, index|
          next unless line.include?(::Elastic::Latest::GitClassProxy::HIGHLIGHT_START_TAG)

          found_line_number = index
          highlight_found = true
          break
        end

        from = if found_line_number >= num_context_lines
                 found_line_number - num_context_lines
               else
                 found_line_number
               end

        to = if (total_lines - found_line_number) >= (num_context_lines + 1)
               found_line_number + num_context_lines
             else
               found_line_number
             end

        data = content.lines[from..to]
        # only send highlighted line number if a highlight was returned by Elasticsearch
        highlight_line = highlight_found ? found_line_number + 1 : nil

        ::Gitlab::Search::FoundBlob.new(
          {
            path: path,
            basename: basename,
            ref: ref,
            startline: from + 1,
            highlight_line: highlight_line,
            data: data.join,
            project: project,
            project_id: project_id,
            group: group,
            group_id: group_id,
            group_level_blob: group_level_blob
          }.compact
        )
      end

      def self.extract_ref_from_result(source)
        source['type'].eql?('wiki_blob') ? source['commit_sha'] : source['blob']['commit_sha']
      end

      def self.extract_path_from_result(source)
        source['type'].eql?('wiki_blob') ? source['path'] : source['blob']['path'] || ''
      end

      def self.extract_content_from_result(source)
        source['type'].eql?('wiki_blob') ? source['content'] : source['blob']['content']
      end

      def self.group_level_result?(source, container = nil)
        return true if container.is_a?(::Group)
        return false if container.is_a?(::Project)

        source['project_id'].blank?
      end

      def self.get_highlight_content(result)
        content_key = result['_source']['type'].eql?('wiki_blob') ? 'content' : 'blob.content'
        result.dig('highlight', content_key)&.first || ''
      end

      def initialize(current_user, query, **opts)
        @current_user = current_user
        @query = query
        @root_ancestor_ids = opts.fetch(:root_ancestor_ids, nil)
        @public_and_internal_projects = opts.fetch(:public_and_internal_projects, true)
        @order_by = opts.fetch(:order_by, nil)
        @sort = opts.fetch(:sort, nil)
        @filters = opts.fetch(:filters, {})
      end

      def failed?(scope)
        return false if handler_for_scope(scope)

        result = send(scope) # rubocop:disable GitlabSecurity/PublicSend -- scope method must be defined in class
        result.respond_to?(:failed?) ? result.failed? : false
      end

      # Used only for zoekt
      def server_error?
        false
      end

      def error_type(scope)
        return if handler_for_scope(scope)

        result = send(scope) # rubocop:disable GitlabSecurity/PublicSend -- scope method must be defined in class
        result.respond_to?(:error_type) ? result.error_type : nil
      end

      def error(scope)
        return false if handler_for_scope(scope)

        result = send(scope) # rubocop:disable GitlabSecurity/PublicSend -- scope method must be defined in class
        result.respond_to?(:error) ? result.error : false
      end

      def objects(scope, page: 1, per_page: DEFAULT_PER_PAGE, preload_method: nil)
        page = (page || 1).to_i

        if handler_for_scope(scope)
          return delegate_to_handler(scope, :objects, page: page, per_page: per_page, preload_method: preload_method)
        end

        scoped_objects(scope, page: page, per_page: per_page, preload_method: preload_method)
      end

      def scoped_objects(scope, page:, per_page:, preload_method:)
        case scope
        when 'projects'
          eager_load(projects, page, per_page, preload_method, [:route, :namespace, :topics, :creator])
        when 'issues'
          issues(scope: 'issues', page: page, per_page: per_page, preload_method: preload_method).paginated_array
        when 'work_items'
          work_items(page: page, per_page: per_page, preload_method: preload_method).paginated_array
        when 'merge_requests'
          eager_load(merge_requests, page, per_page, preload_method, target_project: [:route, :namespace])
        when 'milestones'
          eager_load(milestones, page, per_page, preload_method, project: [:route, :namespace], group: :route)
        when 'notes'
          eager_load(notes, page, per_page, preload_method, project: [:invited_groups, :route, :namespace])
        when 'epics'
          epics(page: page, per_page: per_page, preload_method: preload_method).paginated_array
        when 'blobs'
          blobs(page: page, per_page: per_page, preload_method: preload_method)
        when 'wiki_blobs'
          wiki_blobs(page: page, per_page: per_page)
        when 'commits'
          commits(page: page, per_page: per_page, preload_method: preload_method)
        when 'users'
          users(page: page, per_page: per_page, preload_method: preload_method)
        else
          Kaminari.paginate_array([])
        end
      end

      # Pull the highlight attribute out of Elasticsearch results
      # and map it to the result id
      def highlight_map(scope)
        return delegate_to_handler(scope, :highlight_map) if handler_for_scope(scope)

        case scope
        when 'projects'
          create_map(projects)
        when 'issues'
          issues.highlight_map
        when 'work_items'
          work_items.highlight_map
        when 'merge_requests'
          create_map(merge_requests)
        when 'milestones'
          create_map(milestones)
        when 'notes'
          create_map(notes)
        else
          {}
        end
      rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError
        {}
      end

      def formatted_count(scope)
        return delegate_to_handler(scope, :formatted_count) if handler_for_scope(scope)

        scoped_formatted_count(scope)
      end

      def scoped_formatted_count(scope)
        case scope
        when 'projects'
          elastic_search_limited_counter_with_delimiter(projects_count)
        when 'notes'
          elastic_search_limited_counter_with_delimiter(notes_count)
        when 'blobs'
          elastic_search_limited_counter_with_delimiter(blobs_count)
        when 'wiki_blobs'
          elastic_search_limited_counter_with_delimiter(wiki_blobs_count)
        when 'commits'
          elastic_search_limited_counter_with_delimiter(commits_count)
        when 'issues'
          elastic_search_limited_counter_with_delimiter(issues_count)
        when 'work_items'
          elastic_search_limited_counter_with_delimiter(work_items_count)
        when 'merge_requests'
          elastic_search_limited_counter_with_delimiter(merge_requests_count)
        when 'epics'
          elastic_search_limited_counter_with_delimiter(epics_count)
        when 'milestones'
          elastic_search_limited_counter_with_delimiter(milestones_count)
        when 'users'
          elastic_search_limited_counter_with_delimiter(users_count)
        end
      rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError
        elastic_search_limited_counter_with_delimiter(0)
      end

      def projects_count
        @projects_count ||= if strong_memoized?(:projects)
                              projects.total_count
                            else
                              projects(count_only: true).total_count
                            end
      end

      def notes_count
        @notes_count ||= if strong_memoized?(:notes)
                           notes.total_count
                         else
                           notes(count_only: true).total_count
                         end
      end

      def users_count
        @users_count ||= if strong_memoized?(:users)
                           users.total_count
                         else
                           users(count_only: true).total_count
                         end
      end

      def blobs_count
        @blobs_count ||= if strong_memoized?(:blobs)
                           blobs.total_count
                         else
                           blobs(count_only: true).total_count
                         end
      end

      def wiki_blobs_count
        @wiki_blobs_count ||= if strong_memoized?(:wiki_blobs)
                                wiki_blobs.total_count
                              else
                                wiki_blobs(count_only: true).total_count
                              end
      end

      def commits_count
        @commits_count ||= if strong_memoized?(:commits)
                             commits.total_count
                           else
                             commits(count_only: true).total_count
                           end
      end

      def issues_count
        @issues_count ||= if strong_memoized?(:issues)
                            issues.total_count
                          else
                            issues(scope: 'issues', count_only: true).total_count
                          end
      end

      def work_items_count
        @work_items_count ||= if strong_memoized?(:work_items)
                                work_items.total_count
                              else
                                work_items(count_only: true).total_count
                              end
      end

      def merge_requests_count
        @merge_requests_count ||= if strong_memoized?(:merge_requests)
                                    merge_requests.total_count
                                  else
                                    merge_requests(count_only: true).total_count
                                  end
      end

      def epics_count
        @epics_count ||= if strong_memoized?(:epics)
                           epics.total_count
                         else
                           epics(count_only: true).total_count
                         end
      end

      def milestones_count
        @milestones_count ||= if strong_memoized?(:milestones)
                                milestones.total_count
                              else
                                milestones(count_only: true).total_count
                              end
      end

      # mbergeron: these aliases act as an adapter to the Gitlab::SearchResults
      # interface, which is mostly implemented by this class.
      alias_method :limited_projects_count, :projects_count
      alias_method :limited_notes_count, :notes_count
      alias_method :limited_blobs_count, :blobs_count
      alias_method :limited_wiki_blobs_count, :wiki_blobs_count
      alias_method :limited_commits_count, :commits_count
      alias_method :limited_issues_count, :issues_count
      alias_method :limited_merge_requests_count, :merge_requests_count
      alias_method :limited_milestones_count, :milestones_count

      def aggregations(scope)
        case scope
        when 'blobs'
          blob_aggregations
        when 'issues'
          issue_aggregations
        when 'work_items'
          work_item_aggregations
        when 'merge_requests'
          merge_request_aggregations
        else
          []
        end
      end

      # TODO add call to Vulnerability Query builder https://gitlab.com/gitlab-org/gitlab/-/issues/525479
      def counts(*)
        {}
      end

      private

      # Apply some eager loading to the `records` of an ES result object without
      # losing pagination information. Also, take advantage of preload method if
      # provided by the caller.
      def eager_load(es_result, page, per_page, preload_method, eager)
        paginated_base = es_result.page(page).per(per_page)
        relation = paginated_base.records.includes(eager) # rubocop:disable CodeReuse/ActiveRecord
        relation = relation.public_send(preload_method) if preload_method # rubocop:disable GitlabSecurity/PublicSend

        Kaminari.paginate_array(
          relation.to_a,
          total_count: paginated_base.total_count,
          limit: per_page,
          offset: per_page * (page - 1)
        )
      end

      def base_options
        {
          current_user: current_user,
          public_and_internal_projects: public_and_internal_projects,
          order_by: order_by,
          sort: sort,
          search_level: 'global'
        }
      end

      def add_related_ids(options, name)
        search_feature_enabled = [MergeRequest.name, Issue.name].include?(name)

        if search_feature_enabled && !::Gitlab::Saas.feature_available?(:advanced_search)
          options[:related_ids] = related_ids_for_notes(name)
        end

        options
      end

      def work_item_types_provider
        ::WorkItems::TypesFramework::Provider.new
      end
      strong_memoize_attr :work_item_types_provider

      def scope_options(scope)
        case scope
        when :projects
          base_options.merge(filters.slice(:include_archived, :autocomplete))
        when :notes, :commits, :milestones
          base_options.merge(filters.slice(:include_archived))
        when :merge_requests
          base_options.merge(add_related_ids(merge_request_scope_options, MergeRequest.name))
        when :issues
          add_related_ids(work_item_scope_options(scope: 'issues'), Issue.name)
        when :work_items
          add_related_ids(work_item_scope_options(scope: 'work_items'), Issue.name)
        when :epics
          work_item_scope_options(scope: 'epics').merge(
            klass: WorkItem,
            work_item_type_ids: [work_item_types_provider.find_by_base_type(:epic).id]
          ).except(:fields)
        when :users
          user_scope_options
        when :blobs
          base_options.merge(filters.slice(:language, :include_archived, :num_context_lines))
        when :wiki_blobs
          base_options.merge(root_ancestor_ids: root_ancestor_ids).merge(filters.slice(:include_archived))
        else
          base_options
        end
      end

      def work_item_scope_options(scope: nil)
        epic_type_id = EPIC_TYPE_ID

        # Determine not_work_item_type_ids based on scope:
        # - For 'issues' scope: exclude epics (to show only project-level work items)
        # - For all other scopes: include all types (nil)
        not_work_item_type_ids = scope == 'issues' ? [epic_type_id].compact : nil

        work_item_scope_options = base_options.merge(
          {
            klass: WorkItem, # Load both project-level and group-level work items
            index_name: ::Search::Elastic::References::WorkItem.index,
            not_work_item_type_ids: not_work_item_type_ids
          },
          filters.slice(*::Search::Elastic::References::WorkItem::PERMITTED_FILTER_KEYS)
        )

        # Handle work_item_type_ids filter (only when scope is work_items)
        if scope == 'work_items' && filters[:work_item_type_ids].present?
          work_item_scope_options[:work_item_type_ids] = Array(filters[:work_item_type_ids]).map(&:to_i)
          work_item_scope_options.delete(:not_work_item_type_ids)
        end

        work_item_scope_options
      end

      def user_scope_options
        base_options.merge(
          {
            admin: current_user&.can_admin_all_resources?,
            routing_disabled: true
          },
          filters.slice(:autocomplete)
        )
      end

      def scope_results(scope, klass, count_only:)
        options = scope_options(scope).merge(count_only: count_only)

        strong_memoize(memoize_key(scope, count_only: count_only)) do
          klass.elastic_search(query, options: options)
        end
      end

      def memoize_key(scope, count_only:)
        count_only ? :"#{scope}_results_count" : scope
      end

      def projects(count_only: false)
        scope_results :projects, Project, count_only: count_only
      end

      def issues(scope: 'issues', page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        strong_memoize(memoize_key('issues', count_only: count_only)) do
          options = scope_options(scope.to_sym).merge(count_only: count_only, per_page: per_page,
            page: page, preload_method: preload_method)

          search_query = ::Search::Elastic::WorkItemQueryBuilder.build(query: query, options: options)

          ::Gitlab::Search::Client.execute_search(query: search_query, options: options) do |response|
            ::Search::Elastic::ResponseMapper.new(response, options)
          end
        end
      end

      def work_items(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        strong_memoize(memoize_key('work_items', count_only: count_only)) do
          issues(
            scope: 'work_items',
            page: page,
            per_page: per_page,
            count_only: count_only,
            preload_method: preload_method
          )
        end
      end

      def milestones(count_only: false)
        scope_results :milestones, Milestone, count_only: count_only
      end

      def merge_requests(count_only: false)
        scope_results :merge_requests, MergeRequest, count_only: count_only
      end

      def notes(count_only: false)
        scope_results :notes, Note, count_only: count_only
      end

      def related_ids_for_notes(noteable_type)
        strong_memoize_with(:related_ids_for_notes, noteable_type) do
          options = scope_options(:notes).merge(count_only: false, noteable_type: noteable_type, related_ids_only: true)

          notes_response = Note.elastic_search(query, options: options).response
          notes_response['hits']['hits'].filter_map { |hit| hit['_source']['noteable_id'] }.uniq
        end
      end

      def epics(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        strong_memoize(memoize_key('epics', count_only: count_only)) do
          options = scope_options(:epics)
            .merge(count_only: count_only, per_page: per_page, page: page, preload_method: preload_method)
          search_query = ::Search::Elastic::WorkItemQueryBuilder.build(query: query, options: options)
          ::Gitlab::Search::Client.execute_search(query: search_query, options: options) do |response|
            ::Search::Elastic::ResponseMapper.new(response, options)
          end
        end
      end

      def users(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        return Kaminari.paginate_array([]) unless allowed_to_read_users?

        strong_memoize(memoize_key(:users, count_only: count_only)) do
          users = scope_results(:users, User, count_only: count_only)
          eager_load(users, page, per_page, preload_method, [:status])
        end
      end

      def blobs(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        return Kaminari.paginate_array([]) if query.blank?

        strong_memoize(memoize_key(:blobs, count_only: count_only)) do
          Repository.__elasticsearch__.elastic_search_as_found_blob(
            query,
            page: (page || 1).to_i,
            per: per_page,
            options: scope_options(:blobs).merge(count_only: count_only),
            preload_method: preload_method
          )
        end
      end

      def wiki_blobs(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false)
        return Kaminari.paginate_array([]) if query.blank?

        strong_memoize(memoize_key(:wiki_blobs, count_only: count_only)) do
          Wiki.__elasticsearch__.elastic_search_as_wiki_page(
            query,
            page: (page || 1).to_i,
            per: per_page,
            options: scope_options(:wiki_blobs).merge(count_only: count_only)
          )
        end
      end

      # We're only memoizing once because this object only ever gets used to show a single page of results
      # during its lifetime. We _must_ memoize the page we want because `#commits_count` does not have any
      # inkling of the current page we're on - if we were to memoize with dynamic parameters we would end up
      # hitting ES twice for any page that's not page 1, and that's something we want to avoid.
      #
      # It is safe to memoize the page we get here because this method is _always_ called before `#commits_count`
      def commits(page: 1, per_page: DEFAULT_PER_PAGE, preload_method: nil, count_only: false)
        return Kaminari.paginate_array([]) if query.blank?

        strong_memoize(memoize_key(:commits, count_only: count_only)) do
          Repository.find_commits_by_message_with_elastic(
            query,
            page: (page || 1).to_i,
            per_page: per_page,
            options: scope_options(:commits).merge(count_only: count_only),
            preload_method: preload_method
          )
        end
      end

      def default_scope
        'projects'
      end

      def elastic_search_limited_counter_with_delimiter(count)
        if count.nil?
          number_with_delimiter(0)
        elsif count >= ELASTIC_COUNT_LIMIT
          "#{number_with_delimiter(ELASTIC_COUNT_LIMIT)}+"
        else
          number_with_delimiter(count)
        end
      end

      def blob_aggregations
        Repository.__elasticsearch__.blob_aggregations(query, base_options)
      end
      strong_memoize_attr :blob_aggregations

      def issue_aggregations
        options = scope_options(:issues).merge(aggregation: true)
        search_query = ::Search::Elastic::WorkItemQueryBuilder.build(query: query, options: options)

        results = ::Gitlab::Search::Client.execute_search(query: search_query, options: options) do |response|
          ::Search::Elastic::ResponseMapper.new(response, options)
        end
        ::Gitlab::Search::AggregationParser.call(results.aggregations)
      end
      strong_memoize_attr :issue_aggregations

      def work_item_aggregations
        options = scope_options(:work_items).merge(aggregation: true)
        search_query = ::Search::Elastic::WorkItemQueryBuilder.build(query: query, options: options)

        results = ::Gitlab::Search::Client.execute_search(query: search_query, options: options) do |response|
          ::Search::Elastic::ResponseMapper.new(response, options)
        end
        ::Gitlab::Search::AggregationParser.call(results.aggregations)
      end
      strong_memoize_attr :work_item_aggregations

      def merge_request_aggregations
        options = base_options.merge(aggregation: true, klass: MergeRequest)

        merge_requests_query = ::Search::Elastic::MergeRequestQueryBuilder.build(query: query, options: options)
        results = ::Gitlab::Search::Client.execute_search(query: merge_requests_query, options: options) do |response|
          ::Search::Elastic::ResponseMapper.new(response, options)
        end
        ::Gitlab::Search::AggregationParser.call(results.aggregations)
      end
      strong_memoize_attr :merge_request_aggregations

      def merge_request_scope_options
        filters.slice(
          :order_by,
          :sort,
          :state,
          :include_archived,
          :source_branch,
          :not_source_branch,
          :target_branch,
          :not_target_branch,
          :author_username,
          :not_author_username,
          :assignee_ids,
          :not_assignee_ids,
          :created_after,
          :created_before,
          :updated_after,
          :updated_before,
          :label_name,
          :fields
        )
      end

      def allowed_to_read_users?
        Ability.allowed?(current_user, :read_users_list)
      end

      def create_map(results)
        results.to_h { |x| [x[:_source][:id], x[:highlight]] } if results.present?
      end
    end
  end
end
