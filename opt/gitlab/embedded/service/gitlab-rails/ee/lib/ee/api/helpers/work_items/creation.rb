# frozen_string_literal: true

module EE
  module API
    module Helpers
      module WorkItems
        module Creation
          extend ::Gitlab::Utils::Override

          private

          override :extract_feature_params
          def extract_feature_params(work_item_type, resource_parent)
            feature_params = super

            resolve_iteration_param(feature_params[:iteration_widget], resource_parent)
            resolve_status_param(feature_params[:status_widget], resource_parent)

            feature_params
          end

          def resolve_iteration_param(iteration_params, resource_parent)
            return unless iteration_params.is_a?(Hash) && iteration_params.key?(:iteration_id)

            iteration_id = iteration_params.delete(:iteration_id)
            return iteration_params[:iteration] = nil unless iteration_id

            iteration = IterationsFinder.new(
              current_user,
              parent: resource_parent,
              include_ancestors: true,
              id: iteration_id
            ).execute.first
            not_found!('Iteration') unless iteration

            iteration_params[:iteration] = iteration
          end

          def resolve_status_param(status_params, resource_parent)
            return unless status_params.is_a?(Hash) && status_params.key?(:status_id)

            status_id = status_params.delete(:status_id)
            return unless status_id

            # The namespace determines the lookup strategy, custom and system-defined
            # statuses are mutually exclusive per root namespace. The Status callback
            # validates that the status belongs to the work item's lifecycle via
            # lifecycle.has_status_id?
            namespace = resource_parent.root_ancestor
            status = ::WorkItems::Statuses::Finder.new(namespace, { 'status_id' => status_id }).find_single_status

            not_found!('Status') unless status

            status_params[:status] = status
          end
        end
      end
    end
  end
end
