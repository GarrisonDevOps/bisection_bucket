# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Base
        module GraphqlTool
          extend ActiveSupport::Concern

          EE_QUERIES_ROOT = Rails.root.join('ee/app/graphql/queries/mcp').freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :read_graphql_file
            def read_graphql_file(relative_path)
              ee_query_path = EE_QUERIES_ROOT.join(relative_path)

              return File.read(ee_query_path) if File.exist?(ee_query_path)

              super
            end
          end
        end
      end
    end
  end
end
