# frozen_string_literal: true

module Admin
  module Geo
    class ReplicablesController < Admin::Geo::ApplicationController
      before_action :check_license!
      before_action :render_replicable_group_overview, only: :index
      before_action :set_replicator_class, only: [:index, :show]
      before_action :set_replicator_with_id, only: :show
      before_action :load_node_data, only: [:index, :show]

      def index
        # A disabled replicable still resolves to a replicator class, so the page would
        # otherwise render an empty table with nothing explaining why.
        unless @replicator_class.replication_enabled?
          return redirect_to admin_geo_nodes_path,
            notice: format(s_('Geo|Replication of %{replicable_title} is disabled on this site.'),
              replicable_title: @replicator_class.replicable_title_plural)
        end

        redirect_legacy_route if legacy_route?
      end

      def show; end

      def set_replicator_class
        replicable_name = replicable_name_plural.singularize

        @replicator_class = Gitlab::Geo::Replicator.for_replicable_name(replicable_name)
      rescue NotImplementedError
        render_404
      end

      def set_replicator_with_id
        replicable_id = params.permit(:replicable_id)[:replicable_id].to_i
        return render_404 if replicable_id <= 0

        replicable_name = replicable_name_plural.singularize

        @replicator = Gitlab::Geo::Replicator.for_replicable_params(replicable_name:, replicable_id:)
      rescue NotImplementedError
        render_404
      end

      def replicable_name_plural
        params.permit(:replicable_name_plural)[:replicable_name_plural]
      end

      private

      # Runs before set_replicator_class so a group slug (e.g. "uploads") still works
      # when no replicator is registered under that name. An enabled replicator with
      # the same name wins, so the legacy "uploads" page keeps working until it is removed.
      def render_replicable_group_overview
        enabled_classes = ::Gitlab::Geo.replication_enabled_replicator_classes
        return if enabled_classes.any? { |klass| klass.replicable_name_plural == replicable_name_plural }

        @group_replicator_classes = enabled_classes
          .select { |klass| klass.replicable_group == replicable_name_plural }
          .sort_by(&:replicable_title_plural)
        return if @group_replicator_classes.empty?

        return redirect_legacy_route if legacy_route?

        load_node_data
        render :replicable_group
      end

      def legacy_route?
        params.permit(:id)[:id].blank?
      end

      # legacy routes always get redirected, either to the current node, or
      # if a secondary, we know the ID this should use, so redirect there instead
      def redirect_legacy_route
        redirect_path = if ::Gitlab::Geo.secondary?
                          site_replicables_admin_geo_node_path(
                            id: ::Gitlab::Geo.current_node.id,
                            replicable_name_plural: replicable_name_plural
                          )
                        else
                          admin_geo_nodes_path
                        end

        redirect_to redirect_path
      end
    end
  end
end
