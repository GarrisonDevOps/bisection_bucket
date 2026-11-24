# frozen_string_literal: true

module EE
  # rubocop:disable Gitlab/BoundedContexts -- overriding existing file
  module WikiPages
    module UpdateService
      extend ActiveSupport::Concern

      def group_internal_event_name
        'update_group_wiki_page'
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
