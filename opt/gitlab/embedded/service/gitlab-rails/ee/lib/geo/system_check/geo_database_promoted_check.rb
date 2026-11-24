# frozen_string_literal: true

module Geo
  module SystemCheck
    class GeoDatabasePromotedCheck < ::SystemCheck::BaseCheck
      set_name 'GitLab Geo tracking database is not configured after promotion'
      set_skip_reason 'not a primary node'

      def skip?
        !Gitlab::Geo.primary?
      end

      def check?
        !Gitlab::Geo.geo_database_configured?
      end

      def show_error
        try_fixing_it(
          "It appears this node was promoted to primary but has traces of " \
            "Geo secondary settings in '/etc/gitlab/gitlab.rb'.",
          "Remove or disable previous secondary settings before continuing."
        )

        docs_link = Rails.application.routes.url_helpers.help_page_url(
          'administration/geo/disaster_recovery/_index.md',
          anchor: 'step-6-removing-the-former-secondarys-tracking-database')
        for_more_information(docs_link)
      end
    end
  end
end
