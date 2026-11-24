# frozen_string_literal: true

module Geo
  module SystemCheck
    class EnabledCheck < ::SystemCheck::BaseCheck
      set_name 'GitLab Geo is enabled'

      def check?
        Gitlab::Geo.enabled?
      end

      def show_error
        try_fixing_it(
          'Follow Geo setup instructions to configure primary and secondary nodes'
        )

        for_more_information('doc/administration/geo/index.md')
      end
    end
  end
end
