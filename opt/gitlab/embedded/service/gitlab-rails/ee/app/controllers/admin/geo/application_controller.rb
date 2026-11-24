# frozen_string_literal: true

module Admin
  module Geo
    class ApplicationController < Admin::ApplicationController
      helper ::EE::GeoHelper

      feature_category :geo_replication
      urgency :low

      protected

      def check_license!
        return if Gitlab::Geo.license_allows?

        render_403
      end

      def load_node_data
        # used in replication controllers (replicables, projects, designs) and the
        # navbar data, to figure out which site's data we're trying to access
        @current_node = ::Gitlab::Geo.current_node

        target_node_id = params.permit(:id)[:id]
        @target_node = if target_node_id
                         GeoNode.find(target_node_id)
                       else
                         ::Gitlab::Geo.current_node
                       end
      end
    end
  end
end
