# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Wikis
        module ListWikiPagesTool
          extend ::Gitlab::Utils::Override

          GROUP_QUERY = ::Mcp::Tools::Base::GraphqlTool.load_graphql(
            'wikis/list_group_wiki_pages.query.graphql'
          )

          private

          override :group_wikis_supported?
          def group_wikis_supported?
            true
          end

          override :group_query
          def group_query
            GROUP_QUERY
          end
        end
      end
    end
  end
end
