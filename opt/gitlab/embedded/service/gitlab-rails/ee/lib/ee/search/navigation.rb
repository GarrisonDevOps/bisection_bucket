# frozen_string_literal: true

module EE
  module Search
    module Navigation
      extend ::Gitlab::Utils::Override

      private

      def zoekt_enabled?
        !!options[:zoekt_enabled]
      end

      override :show_code_search_tab?
      def show_code_search_tab?
        return true if super
        return false if project

        global_enabled = ::Gitlab::CurrentSettings.global_search_code_enabled?

        if show_elasticsearch_tabs? && ::Gitlab::CurrentSettings.elasticsearch_code_scope
          return group.present? || global_enabled
        end

        return (group.present? ? ::Search::Zoekt.search?(group) : global_enabled) if zoekt_enabled?

        false
      end

      override :show_wiki_search_tab?
      def show_wiki_search_tab?
        return true if super
        return false if project
        return false unless show_elasticsearch_tabs?
        return true if group

        ::Gitlab::CurrentSettings.global_search_wiki_enabled?
      end

      override :show_commits_search_tab?
      def show_commits_search_tab?
        return true if super # project search & user can search commits
        return false unless show_elasticsearch_tabs? # advanced search enabled
        return true if group # group search

        ::Gitlab::CurrentSettings.global_search_commits_enabled?
      end

      override :show_comments_search_tab?
      def show_comments_search_tab?
        return true if super

        project.nil? && show_elasticsearch_tabs?
      end

      def show_elasticsearch_tabs?
        !!options[:show_elasticsearch_tabs]
      end
    end
  end
end
