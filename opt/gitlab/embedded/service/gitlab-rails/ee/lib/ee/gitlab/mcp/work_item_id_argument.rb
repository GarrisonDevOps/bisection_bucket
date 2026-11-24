# frozen_string_literal: true

module EE
  module Gitlab
    module Mcp
      module WorkItemIdArgument
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          private

          override :work_item_from
          def work_item_from(gid)
            return super unless gid.model_name == 'Epic'

            ::Epic.find_by_id(gid.model_id)&.work_item
          end
        end
      end
    end
  end
end
