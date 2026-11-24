# frozen_string_literal: true

module CodeSuggestions
  module Prompts
    class Base
      include Gitlab::Utils::StrongMemoize

      def initialize(params, current_user, feature_setting = nil)
        @params = params
        @current_user = current_user
        @feature_setting = feature_setting
      end

      private

      attr_reader :params, :current_user, :feature_setting

      def file_name
        params.dig(:current_file, :file_name).to_s
      end

      def extension
        File.extname(file_name).delete_prefix('.')
      end
      strong_memoize_attr :extension

      def language
        ::CodeSuggestions::ProgrammingLanguage.detect_from_filename(file_name)
      end
      strong_memoize_attr :language

      def content_above_cursor
        params.dig(:current_file, :content_above_cursor)
      end

      def content_below_cursor
        params.dig(:current_file, :content_below_cursor)
      end
    end
  end
end
