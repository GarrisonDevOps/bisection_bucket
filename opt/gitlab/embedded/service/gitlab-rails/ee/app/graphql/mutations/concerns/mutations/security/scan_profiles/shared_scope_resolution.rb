# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      module SharedScopeResolution
        MAX_IDS = 100

        private

        def validate_id_limit!(project_ids, group_ids)
          total = project_ids.size + group_ids.size
          return if total <= MAX_IDS

          raise Gitlab::Graphql::Errors::ArgumentError, "Too many ids (maximum: #{MAX_IDS})"
        end

        def shared_root_namespace!(project_ids, group_ids)
          root_namespace_ids = (::Project.root_ids_for(project_ids) + ::Namespace.root_ids_for(group_ids)).to_set
          root_groups = Group.id_in(root_namespace_ids)

          # root_groups.size catches personal namespaces too: they aren't Groups so they drop out here.
          if root_namespace_ids.size != 1 || root_groups.size != 1
            raise Gitlab::Graphql::Errors::ArgumentError, "All items should belong to the same root group"
          end

          root_groups.first
        end

        def load_and_authorize_projects!(project_ids)
          return [] if project_ids.empty?

          all_projects = Project.id_in(project_ids)
          authorized_projects = Ability.filter_allowed(current_user, :apply_security_scan_profiles, all_projects)
          return authorized_projects unless authorized_projects.size != project_ids.size

          raise_resource_not_available_error!
        end

        def load_and_authorize_groups!(group_ids)
          return [] if group_ids.empty?

          all_groups = Group.id_in(group_ids)
          authorized_groups = Ability.filter_allowed(current_user, :apply_security_scan_profiles, all_groups)
          return authorized_groups unless authorized_groups.size != group_ids.size

          raise_resource_not_available_error!
        end
      end
    end
  end
end
