# frozen_string_literal: true

module EE
  module Gitlab
    module Analytics
      module CycleAnalytics
        module RequestParams
          include ::Gitlab::Utils::StrongMemoize
          include ::Gitlab::Allowable
          extend ::Gitlab::Utils::Override

          override :to_data_attributes
          def to_data_attributes
            super.tap do |attrs|
              attrs[:aggregation] = aggregation_attributes if use_aggregated_backend?
              attrs[:group] = group_data_attributes if namespace.present?
              attrs[:projects] = group_projects(project_ids) if group.present? && project_ids.present?
              attrs[:enable_tasks_by_type_chart] = 'true' if group.present?
              attrs[:enable_customizable_stages] = 'true' if licensed?
              attrs[:can_read_cycle_analytics] = 'true' if can_read_cycle_analytics?
              attrs[:enable_projects_filter] = 'true' if group.present? || namespace.is_a?(Group)
              attrs[:enable_vsd_link] = 'true' if render_value_stream_dashboard_link?
              attrs[:can_edit] = 'true' if licensed? && ::Gitlab::Analytics::CycleAnalytics.allowed_to_edit?(
                current_user, namespace)

              add_licensed_filter_params!(attrs)
            end
          end

          override :to_data_collector_params
          def to_data_collector_params
            super.tap do |attrs|
              add_licensed_filter_params!(attrs)
            end
          end

          override :resource_paths
          def resource_paths
            paths = super

            if group.present?
              paths.merge({
                milestones_path: url_helpers.group_milestones_path(group, format: :json),
                labels_path: url_helpers.group_labels_path(group, format: :json),
                new_value_stream_path: url_helpers.new_group_analytics_cycle_analytics_value_stream_path(group),
                edit_value_stream_path: url_helpers.edit_group_analytics_cycle_analytics_value_stream_path(
                  group,
                  ':id'
                )
              })
            elsif project.present?
              paths.merge({
                new_value_stream_path: url_helpers.new_namespace_project_analytics_cycle_analytics_value_stream_path(
                  project.namespace.full_path,
                  project.path
                ),
                edit_value_stream_path: url_helpers.edit_namespace_project_analytics_cycle_analytics_value_stream_path(
                  project.namespace.full_path,
                  project.path,
                  ':id'
                )
              })
            else
              paths
            end
          end

          private

          def can_read_cycle_analytics?
            licensed? && can?(current_user, :read_cycle_analytics, namespace)
          end

          def render_value_stream_dashboard_link?
            (licensed? && group.present?) ||
              (licensed? && project.present? && project.group.present? && can?(current_user,
                :read_group_analytics_dashboards, project.group))
          end

          def add_licensed_filter_params!(attrs)
            return unless licensed?

            self.class::LICENSED_PARAMS.each do |param_name|
              attrs[param_name] = attributes[param_name.to_s] if attributes[param_name.to_s].present?
            end

            self.class::NEGATABLE_PARAMS.each do |param_name|
              attrs[:not] ||= {}
              attrs[:not][param_name] = self.not[param_name] if self.not && self.not[param_name]
            end
          end

          override :namespace_attributes
          def namespace_attributes
            return super if project
            return {} if group.nil?

            {
              name: group.name,
              path: group.full_path,
              rest_api_request_path: "groups/#{group.full_path}",
              type: namespace.type
            }
          end

          override :use_aggregated_backend?
          def use_aggregated_backend?
            super || licensed?
          end

          def aggregation_attributes
            {
              enabled: aggregation.enabled.to_s,
              last_run_at: aggregation.last_incremental_run_at&.iso8601,
              next_run_at: aggregation.estimated_next_run_at&.iso8601
            }
          end

          def aggregation
            @aggregation ||= ::Analytics::CycleAnalytics::Aggregation.safe_create_for_namespace(namespace)
          end

          def group_projects(project_ids)
            ::GroupProjectsFinder.new(
              group: namespace,
              current_user: current_user,
              options: { include_subgroups: true },
              project_ids_relation: project_ids
            )
              .execute
              .with_route
              .map { |project| project_data_attributes(project) }
              .to_json
          end

          def project_data_attributes(project)
            {
              id: project.to_gid.to_s,
              name: project.name,
              path_with_namespace: project.path_with_namespace,
              avatar_url: project.avatar_url
            }
          end

          def group_data_attributes
            return unless namespace

            {
              id: namespace.id,
              namespace_id: namespace.id,
              name: namespace.name,
              full_path: namespace.full_path,
              avatar_url: namespace.avatar_url
            }
          end

          def group
            namespace if namespace.is_a?(Group) && licensed?
          end
          strong_memoize_attr :group

          def licensed?
            ::Gitlab::Analytics::CycleAnalytics.licensed?(namespace)
          end
        end
      end
    end
  end
end
