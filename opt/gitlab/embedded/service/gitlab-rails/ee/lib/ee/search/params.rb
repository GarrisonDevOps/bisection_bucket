# frozen_string_literal: true

module EE
  module Search
    module Params
      extend ::Gitlab::Utils::Override

      private

      override :legacy_scope_map
      def legacy_scope_map
        super.merge('epics' => 'work_items')
      end
    end
  end
end
