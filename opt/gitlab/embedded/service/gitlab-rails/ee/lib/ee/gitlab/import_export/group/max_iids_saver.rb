# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module Group
        module MaxIidsSaver
          extend ActiveSupport::Concern

          EE_RESOURCE_QUERIES = {
            epics: ->(group) { group.epics.maximum(:iid) },
            iterations: ->(group) { group.iterations.maximum(:iid) }
          }.freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :resource_queries
            def resource_queries
              super.merge(EE_RESOURCE_QUERIES)
            end
          end
        end
      end
    end
  end
end
