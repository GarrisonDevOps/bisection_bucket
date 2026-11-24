# frozen_string_literal: true

module EE
  # rubocop:disable Gitlab/BoundedContexts -- overriding existing file
  module WikiPages
    module CreateService
      extend ActiveSupport::Concern

      def group_internal_event_name
        'create_group_wiki_page'
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
