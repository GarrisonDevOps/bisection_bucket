# frozen_string_literal: true

module EE
  module SearchService
    extend ::Gitlab::Utils::Override

    module ClassMethods
      extend ::Gitlab::Utils::Override

      override :supported_search_types
      def supported_search_types
        super + %w[advanced zoekt]
      end
    end

    def self.prepended(base)
      base.singleton_class.prepend ClassMethods
    end

    # This is a proper method instead of a `delegate` in order to
    # avoid adding unnecessary methods to Search::SnippetService
    def use_elasticsearch?
      search_service.use_elasticsearch?
    end

    def show_elasticsearch_tabs?
      ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: search_service.elasticsearchable_scope)
    end

    override :search_type
    def search_type
      search_service.search_type
    end

    def use_zoekt?
      search_service.try(:use_zoekt?)
    end

    override :global_search_enabled_for_scope?
    def global_search_enabled_for_scope?
      case params[:scope]
      when 'blobs'
        ::Gitlab::CurrentSettings.global_search_code_enabled?
      when 'commits'
        ::Gitlab::CurrentSettings.global_search_commits_enabled?
      when 'wiki_blobs'
        ::Gitlab::CurrentSettings.global_search_wiki_enabled?
      else
        super
      end
    end

    override :search_type_errors
    def search_type_errors
      # Check the actual search type being used, not just the param
      current_search_type = params[:search_type] || search_type
      return if current_search_type.nil?

      # Use user_requested_scope (params[:scope]) rather than the resolved scope method,
      # which is memoized and can return nil when the requested scope is filtered out
      # due to search type unavailability, causing validation to silently pass.
      errors = case current_search_type
               when 'advanced' then advanced_search_type_errors
               when 'zoekt' then zoekt_search_type_errors
               when 'basic' then []
               else unknown_search_type_errors
               end

      return if errors.compact.empty?

      errors.compact.join(', ')
    end

    private

    def advanced_search_type_errors
      return [] unless user_requested_scope == 'blobs'

      if !::Gitlab::CurrentSettings.elasticsearch_code_scope
        ["Advanced search is disabled for #{user_requested_scope}"]
      elsif !use_elasticsearch?
        ['Advanced search is not available']
      else
        []
      end
    end

    def zoekt_search_type_errors
      errors = []
      errors << 'Exact code search is not available' unless use_zoekt?

      if user_requested_scope.present? && user_requested_scope != 'blobs'
        errors << 'Exact code search can only be used for blobs'
      end

      errors << zoekt_project_limit_error
      errors
    end

    def unknown_search_type_errors
      return [] unless params[:search_type].present?

      ["Search type should be one of these: #{::SearchService.supported_search_types.join(', ')}"]
    end

    def zoekt_project_limit_error
      return unless params[:group_id].present?
      return if params[:project_id].present?
      return if traversal_id_search_available?
      return unless estimated_project_count > ::Search::Zoekt::Settings.max_projects_for_legacy_search

      ::Gitlab::AppLogger.warn(
        message: 'Zoekt search scope exceeds maximum projects',
        Labkit::Fields::GL_USER_ID => current_user&.id,
        group_id: params[:group_id],
        estimated_project_count: estimated_project_count,
        traversal_id_search_available: traversal_id_search_available?
      )

      "Your search includes too many projects while traversal ID indexing is still in progress. " \
        "Only the first #{::Search::Zoekt::Settings.max_projects_for_legacy_search} projects are shown. " \
        "Please contact your administrator."
    end

    def traversal_id_search_available?
      ::Search::Zoekt.feature_available?(
        :traversal_id_search, current_user, group_id: params[:group_id], project_id: params[:project_id]
      )
    end

    def estimated_project_count
      return 0 unless params[:group_id].present?

      group = ::Group.find_by_id(params[:group_id])
      return 0 unless group

      limit = ::Search::Zoekt::Settings.max_projects_for_legacy_search + 1
      group.all_projects.limit(limit).count
    end
  end
end
