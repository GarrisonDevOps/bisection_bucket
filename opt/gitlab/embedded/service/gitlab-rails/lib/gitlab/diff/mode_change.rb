# frozen_string_literal: true

module Gitlab
  module Diff
    # Gitaly splits a type change into a deletion and an addition, so within one diff file only the executable bit
    # is expected to change.
    class ModeChange
      NO_MODE = '0'
      REGULAR_MODE = '100644'
      EXECUTABLE_MODE = '100755'
      NON_EXECUTABLE_MODES = [NO_MODE, REGULAR_MODE].freeze

      attr_reader :old_mode, :new_mode, :type

      def initialize(old_mode, new_mode)
        @old_mode = old_mode
        @new_mode = new_mode
        @type = classify
      end

      def new_file?
        old_mode == NO_MODE
      end

      def deleted_file?
        new_mode == NO_MODE
      end

      private

      # A new or deleted file that is not executable has no type: its path already shows the change.
      def classify
        return if old_mode.nil? || new_mode.nil? || old_mode == new_mode

        if new_mode == EXECUTABLE_MODE && NON_EXECUTABLE_MODES.include?(old_mode)
          :executable_gained
        elsif old_mode == EXECUTABLE_MODE && NON_EXECUTABLE_MODES.include?(new_mode)
          :executable_lost
        elsif old_mode != NO_MODE && new_mode != NO_MODE
          :other
        end
      end
    end
  end
end
