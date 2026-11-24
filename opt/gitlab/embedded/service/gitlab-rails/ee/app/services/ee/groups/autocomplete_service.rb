# frozen_string_literal: true

module EE
  module Groups
    module AutocompleteService
      include ::Routing::WikiHelper

      # rubocop: disable CodeReuse/ActiveRecord
      def epics(confidential_only: false)
        finder_params = { group_id: group.id }
        finder_params[:confidential] = true if confidential_only.present?

        # TODO: use include_descendant_groups: true optional parameter once frontend supports epics from external groups.
        # See https://gitlab.com/gitlab-org/gitlab/issues/6837
        EpicsFinder.new(current_user, finder_params)
          .execute
          .preload(:group)
          .select(:iid, :title, :group_id)
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def iterations
        finder_params = { parent: group, include_ancestors: true, state: 'opened' }

        IterationsFinder.new(current_user, finder_params).execute.with_cadence
      end

      def wikis
        wiki = ::Wiki.for_container(group, current_user)
        return [] unless can?(current_user, :read_wiki, wiki.container)

        wiki
          .list_pages(limit: 5000, load_content: true, size_limit: 512)
          .reject { |page| page.slug.start_with?('templates/', 'uploads/') }
          .map { |page| { path: wiki_page_path(page.wiki, page), slug: page.slug, title: page.human_title } }
      end

      def vulnerabilities
        ::Autocomplete::VulnerabilitiesAutocompleteFinder
          .new(current_user, group, params)
          .execute
      end
    end
  end
end
