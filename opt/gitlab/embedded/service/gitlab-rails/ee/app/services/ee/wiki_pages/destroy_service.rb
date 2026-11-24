# frozen_string_literal: true

module EE
  # rubocop:disable Gitlab/BoundedContexts -- overriding existing file
  module WikiPages
    module DestroyService
      extend ActiveSupport::Concern

      def group_internal_event_name
        'delete_group_wiki_page'
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
