# frozen_string_literal: true

module Security
  module DependencyFirewall
    module PreventedStats
      # Resolves which group summaries a change affects: the Group namespaces in the traversal ids,
      # limited to hierarchies whose root has the group stats flag enabled.
      module AffectedGroups
        class << self
          def for_projects(project_ids)
            return [] if project_ids.empty? || !Availability.group_prevented_stats_possibly_enabled?

            enabled_group_ids(summary_model.group_traversal_ids_for_projects(project_ids))
          end

          def for_namespaces(namespace_ids)
            return [] if namespace_ids.empty?

            enabled_group_ids(summary_model.group_traversal_ids_for_namespaces(namespace_ids))
          end

          private

          def summary_model
            ::Security::DependencyFirewallNamespacePreventedStat
          end

          def enabled_group_ids(traversal_ids)
            traversal_ids.group_by(&:first)
              .select { |root_id, _| Availability.group_prevented_stats_enabled_for_root_id?(root_id) }
              .values.flatten.uniq
          end
        end
      end
    end
  end
end
