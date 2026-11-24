# frozen_string_literal: true

module EE
  module SearchHelper
    extend ::Gitlab::Utils::Override
    include SafeFormatHelper

    SWITCH_TO_BASIC_SEARCHABLE_TABS = %w[projects issues merge_requests milestones users epics].freeze
    PLACEHOLDER = '_PLACEHOLDER_'

    override :search_filter_input_options
    def search_filter_input_options(type, placeholder = _('Search or filter results…'))
      options = super
      options[:data][:'multiple-assignees'] = 'true' if search_multiple_assignees?(type)

      if @project&.group
        options[:data]['epics-endpoint'] = expose_path(api_v4_groups_epics_path(id: @project.group.id))
      elsif @group.present?
        options[:data]['epics-endpoint'] = expose_path(api_v4_groups_epics_path(id: @group.id))
      end

      if allow_filtering_by_iteration?
        if @project
          options[:data]['iterations-endpoint'] = expose_path(api_v4_projects_iterations_path(id: @project.id))
        elsif @group
          options[:data]['iterations-endpoint'] = expose_path(api_v4_groups_iterations_path(id: @group.id))
        end
      end

      options
    end

    override :search_entries_scope_label
    def search_entries_scope_label(scope, count)
      case scope
      when 'epics'
        ns_('SearchResults|epic', 'SearchResults|epics', count)
      else
        super
      end
    end

    # This is a special case for snippet searches in .com.
    # The scope used to gather the snippets is too wide and
    # we have to process a lot of them, what leads to time outs.
    # We're reducing the scope only in .com because the current
    # one is still valid in smaller installations.
    # https://gitlab.com/gitlab-org/gitlab/issues/26123
    override :search_entries_info_template
    def search_entries_info_template(collection)
      return super unless gitlab_com_snippet_db_search?

      if collection.total_pages > 1
        safe_format(s_("SearchResults|Showing %{from} - %{to} of %{count} %{scope} for %{term_element} in your " \
          "personal and project snippets"), from: from, to: to, count: count, scope: scope, term_element: term_element)
      else
        safe_format(s_("SearchResults|Showing %{count} %{scope} for %{term_element} in your personal and project " \
          "snippets"), count: count, scope: scope, term_element: term_element)
      end
    end

    override :highlight_and_truncate_issuable
    def highlight_and_truncate_issuable(issuable, search_term, search_highlight)
      search_highlight = search_highlight&.with_indifferent_access
      return super unless search_service.use_elasticsearch? && search_highlight.dig(issuable.id, 'description').present?

      # We use Elasticsearch highlighting for results from Elasticsearch. Sanitize the description, replace the
      # pre/post tags from Elasticsearch with highlighting, truncate, and mark as html_safe. HTML tags are not
      # counted towards the character limit.
      text = search_sanitize(search_highlight.dig(issuable.id, 'description').first)
      text.gsub!(::Elastic::Latest::GitClassProxy::HIGHLIGHT_START_TAG, '<mark>')
      text.gsub!(::Elastic::Latest::GitClassProxy::HIGHLIGHT_END_TAG, '</mark>')

      return text if text.blank?

      search_truncate(text).html_safe
    end

    override :search_sort_options
    def search_sort_options
      original_options = super

      options = []

      if search_service.use_elasticsearch?
        options << {
          title: _('Most relevant'),
          sortable: false,
          sortParam: 'relevant'
        }
      end

      options + original_options
    end

    override :search_scope
    def search_scope
      return if ::Gitlab::CurrentSettings.custom_default_search_scope_set?

      if current_controller?(:epics)
        'epics'
      else
        super
      end
    end

    override :wiki_blob_link
    def wiki_blob_link(wiki_blob)
      return group_wiki_path(wiki_blob.group, wiki_blob.basename) if wiki_blob.group_level_blob

      super
    end

    override :should_show_zoekt_results?
    def should_show_zoekt_results?(scope, search_type)
      return false unless scope == 'blobs' && search_type == 'zoekt'

      @project.blank? || @project.default_branch == repository_ref(@project) || super
    end

    override :blob_data_oversize_message
    def blob_data_oversize_message
      return super unless ::Gitlab::CurrentSettings.elasticsearch_search?

      max_file_size_indexed = ::Gitlab::CurrentSettings.elasticsearch_indexed_file_size_limit_kb.kilobytes
      format(
        _('The file could not be displayed because it is empty or larger than the ' \
          'maximum file size indexed (%{size}).'), size: number_to_human_size(max_file_size_indexed)
      )
    end

    private

    override :combined_generic_results
    def combined_generic_results
      super + default_autocomplete_ai_catalog
    end

    # Autocomplete results for AI catalog pages
    def default_autocomplete_ai_catalog
      return [] unless current_user && ::Ai::Catalog.feature_available?

      [
        {
          category: "Jump to",
          id: "ai_catalog_agents",
          label: _("Explore / AI Catalog (Agents)"),
          url: explore_ai_catalog_agents_path
        },
        {
          category: "Jump to",
          id: "ai_catalog_flows",
          label: _("Explore / AI Catalog (Flows)"),
          url: explore_ai_catalog_flows_path
        }
      ]
    end

    def search_multiple_assignees?(type)
      context = @project.presence || @group.presence || :dashboard

      type == :issues && (context == :dashboard ||
        context.feature_available?(:multiple_issue_assignees))
    end

    def allow_filtering_by_iteration?
      # We currently only have group-level iterations so we hide
      # this filter for projects under personal namespaces
      return false if @project && @project.namespace.user_namespace?

      context = @project.presence || @group.presence

      context&.feature_available?(:iterations)
    end

    def gitlab_com_snippet_db_search?
      @current_user &&
        search_service.show_snippets? &&
        ::Gitlab.com? &&
        ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: nil)
    end

    override :nav_options
    def nav_options
      super.merge(
        show_elasticsearch_tabs: search_service.show_elasticsearch_tabs?,
        zoekt_enabled: ::Search::Zoekt.search?(@project.presence || @group.presence)
      )
    end

    def work_item_status_for_issuable(issuable)
      return unless License.feature_available?(:work_item_status)
      return unless issuable.respond_to?(:status_with_fallback)

      status = issuable.status_with_fallback
      return unless status

      {
        id: status.id,
        name: status.name,
        color: status.color,
        category: status.category,
        description: status.description,
        icon_name: status.icon_name
      }
    end
  end
end
