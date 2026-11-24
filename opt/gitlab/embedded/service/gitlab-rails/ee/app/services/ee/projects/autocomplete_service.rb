# frozen_string_literal: true

module EE
  module Projects
    module AutocompleteService
      extend ::Gitlab::Utils::Override

      override :issues
      def issues
        project_items = super

        if should_include_group_items?(project_items)
          project_items + fetch_group_items(project_items.size)
        else
          project_items
        end
      end

      def epics
        EpicsFinder
          .new(current_user, group_id: project.group&.id, state: 'opened')
          .execute
          .with_group_route
          .select(:iid, :title, :group_id)
      end

      def iterations
        finder_params = { parent: project.group, include_ancestors: true, state: 'opened' }

        IterationsFinder.new(current_user, finder_params).execute.with_cadence
      end

      def vulnerabilities
        ::Autocomplete::VulnerabilitiesAutocompleteFinder
          .new(current_user, project, params)
          .execute
      end

      private

      def should_include_group_items?(project_items)
        project_items.size < ::Projects::AutocompleteService::SEARCH_LIMIT &&
          project.group&.allow_group_items_in_project_autocompletion?
      end

      def fetch_group_items(current_count)
        remaining_slots = ::Projects::AutocompleteService::SEARCH_LIMIT - current_count
        group_items = ::WorkItems::WorkItemsFinder.new(
          current_user,
          group_id: project.group.id,
          state: 'opened',
          include_descendants: false
        ).execute

        group_items = group_items.gfm_autocomplete_search(params[:search]) if params[:search]

        group_items
          .select(:iid, :title, :namespace_id, :work_item_type_id)
          .limit(remaining_slots)
      end
    end
  end
end
