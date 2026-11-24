# frozen_string_literal: true

module Search
  module Zoekt
    class Logger < ::Gitlab::JsonLogger
      def self.file_name_noext
        'zoekt'
      end
    end
  end
end
