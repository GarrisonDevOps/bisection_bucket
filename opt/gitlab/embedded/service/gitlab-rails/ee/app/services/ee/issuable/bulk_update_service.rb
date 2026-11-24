# frozen_string_literal: true

module EE
  module Issuable
    module BulkUpdateService
      extend ::Gitlab::Utils::Override

      override :update_class
      def update_class(type)
        return super unless type.classify.constantize == ::Epic

        ::WorkItems::LegacyEpics::UpdateService
      end

      private

      override :find_issuables
      def find_issuables(parent, model_class, ids)
        return super unless model_class == ::Epic

        model_class
          .id_in(ids)
          .in_selected_groups(parent.self_and_descendants)
          .includes_for_bulk_update
      end

      override :permitted_attrs
      def permitted_attrs(type)
        return super unless type == 'issue'

        super.push(:health_status, :epic_id, :sprint_id, :status)
      end

      override :set_update_params
      def set_update_params(type)
        super

        set_health_status
        set_epic_param
        set_status_param
      end

      def set_health_status
        return unless params[:health_status].present?

        params[:health_status] = nil if params[:health_status] == IssuableFinder::Params::NONE.to_s
      end

      def set_epic_param
        return unless params[:epic_id].present?

        epic_id = params.delete(:epic_id)
        params[:epic] = find_epic(epic_id)
      end

      def set_status_param
        return unless params[:status].present?

        status_id = params.delete(:status)
        params[:status] = find_status(status_id)
      end

      def find_epic(epic_id)
        return if remove_epic?(epic_id)

        EpicsFinder.new(current_user, group_id: group&.id, include_ancestor_groups: true).find(epic_id)
      rescue ActiveRecord::RecordNotFound
        raise ArgumentError, _('Epic not found for given params')
      end

      def find_status(status_id)
        gid = ::GitlabSchema.parse_gid(status_id, expected_type: ::WorkItems::Statuses::Status)
        status = ::WorkItems::Statuses::Finder.new(
          parent.root_ancestor, { 'status_id' => gid.model_id }
        ).find_single_status

        raise ArgumentError, _('Status not found for given params') unless status

        status
      end

      def remove_epic?(epic_id)
        epic_id == IssuableFinder::Params::NONE.to_s
      end

      def epics_available?
        group&.feature_available?(:epics)
      end

      def group
        parent.is_a?(Group) ? parent : parent.group
      end
    end
  end
end
