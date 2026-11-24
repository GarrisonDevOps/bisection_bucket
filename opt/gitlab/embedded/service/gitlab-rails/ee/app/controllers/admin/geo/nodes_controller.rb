# frozen_string_literal: true

module Admin
  module Geo
    class NodesController < Admin::Geo::ApplicationController
      before_action :check_license!, except: :index
      before_action :load_node, only: [:edit, :update]

      before_action do
        push_frontend_feature_flag(:org_mover_extend_selective_sync_to_primary_checksumming, type: :ops)
      end

      def create
        @node = ::Geo::NodeCreateService.new(geo_node_params).execute

        if @node.persisted?
          flash[:toast] = _('Node was successfully created.')
          redirect_to admin_geo_nodes_path
        else
          @nodes = GeoNode.all

          render :form
        end
      end

      def new
        @form_title = _('Add New Site')
        render :form
      end

      def edit
        @form_title = _('Edit Geo Site')
        render :form
      end

      def update
        if ::Geo::NodeUpdateService.new(@node, geo_node_params).execute
          flash[:toast] = _('Node was successfully updated.')
          redirect_to admin_geo_nodes_path
        else
          render :form
        end
      end

      private

      def geo_node_params
        permitted_hash_params = {
          selective_sync_shards: []
        }

        permitted_hash_params[:organization_ids] = [] if ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?

        params.require(:geo_node).permit(
          :name,
          :url,
          :internal_url,
          :primary,
          :selective_sync_type,
          :namespace_ids,
          :repos_max_capacity,
          :files_max_capacity,
          :verification_max_capacity,
          :minimum_reverification_interval,
          :container_repositories_max_capacity,
          :sync_object_storage,
          **permitted_hash_params
        )
      end

      def load_node
        @node = GeoNode.find(params.permit(:id)[:id])
        @serialized_site = GeoNodeSerializer.new.represent(@node).to_json
      end
    end
  end
end
