# frozen_string_literal: true

module Geo
  module SystemCheck
    class DatabaseReplicationEnabledCheck < ::SystemCheck::BaseCheck
      set_name 'Database replication enabled?'
      set_skip_reason 'not a secondary node'

      def skip?
        !Gitlab::Geo.secondary?
      end

      def check?
        geo_health_check.replication_enabled?
      end

      def show_error
        return if Gitlab::Geo.postgresql_replication_agnostic_enabled?

        try_fixing_it(
          'Follow Geo setup instructions to configure primary and secondary nodes for replication'
        )

        docs_link = Rails.application.routes.url_helpers.help_page_url('administration/geo/setup/database.md')
        for_more_information(docs_link)
      end

      private

      def geo_health_check
        @geo_health_check ||= Gitlab::Geo::HealthCheck.new
      end
    end
  end
end
