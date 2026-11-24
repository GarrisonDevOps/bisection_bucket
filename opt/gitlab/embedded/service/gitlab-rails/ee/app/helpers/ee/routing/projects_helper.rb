# frozen_string_literal: true

module EE
  module Routing
    module ProjectsHelper
      extend ::Gitlab::Utils::Override

      override :work_item_url
      def work_item_url(entity, *args)
        if (entity.is_a?(::Epic) || entity.group_epic_work_item?) && !entity.use_work_item_url?
          group_epic_url(entity.namespace, entity, *args)
        else
          super
        end
      end
    end
  end
end
