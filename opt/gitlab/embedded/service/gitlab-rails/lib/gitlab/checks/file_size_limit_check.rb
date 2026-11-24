# frozen_string_literal: true

module Gitlab
  module Checks
    class FileSizeLimitCheck < BaseBulkChecker
      include ActionView::Helpers::NumberHelper

      def validate!
        nil
      end

      private

      # rubocop:disable Gitlab/NoCodeCoverageComment -- This is fully overridden in EE,Lint/MissingCopEnableDirective
      # simplecov:disable
      def file_size_limit
        nil
      end
      # simplecov:enable
      # rubocop:enable Gitlab/NoCodeCoverageComment
    end
  end
end

Gitlab::Checks::FileSizeLimitCheck.prepend_mod
