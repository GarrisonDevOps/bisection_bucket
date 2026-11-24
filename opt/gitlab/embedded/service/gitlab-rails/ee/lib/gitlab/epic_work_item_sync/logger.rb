# frozen_string_literal: true

module Gitlab
  module EpicWorkItemSync
    class Logger < ::Gitlab::JsonLogger
      def self.file_name_noext
        'epic_work_item_sync'
      end
    end
  end
end
