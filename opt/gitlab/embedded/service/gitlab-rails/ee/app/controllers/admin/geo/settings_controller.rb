# frozen_string_literal: true

module Admin
  module Geo
    class SettingsController < Admin::ApplicationSettingsController
      helper ::EE::GeoHelper
      before_action :check_license!, except: :show

      feature_category :geo_replication
      urgency :low

      def show; end

      protected

      def check_license!
        return if Gitlab::Geo.license_allows?

        render_403
      end
    end
  end
end
