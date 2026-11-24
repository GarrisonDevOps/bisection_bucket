# frozen_string_literal: true

module EE
  module Nav
    module NewDropdownHelper
      extend ::Gitlab::Utils::Override

      private

      override :create_group_wiki_menu_item
      def create_group_wiki_menu_item(group)
        if can?(current_user, :create_wiki, group)
          ::Gitlab::Nav::TopNavMenuItem.build(
            id: 'new_wiki_page',
            title: _('New wiki page'),
            href: group_wikis_new_path(group)
          )
        end
      end
    end
  end
end
