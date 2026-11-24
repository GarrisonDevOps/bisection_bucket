# frozen_string_literal: true

module Geo
  module SystemCheck
    class GeoNodesCheck < ::SystemCheck::BaseCheck
      # Adding this check here due to this issue: https://gitlab.com/gitlab-org/gitlab/-/issues/550285
      set_name 'PG Replication is setup'

      def check?
        GeoNode.connection.table_exists?(:geo_nodes)
      end

      def show_error
        try_fixing_it(
          'GeoNode table does not exist - please follow Geo docs to set up this node'
        )

        for_more_information('doc/administration/geo/index.md')
      end
    end
  end
end
