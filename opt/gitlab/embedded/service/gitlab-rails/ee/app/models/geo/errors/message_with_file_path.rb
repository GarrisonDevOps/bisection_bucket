# frozen_string_literal: true

module Geo
  module Errors
    # Builds error messages with file paths, truncating long paths to fit in 255 characters
    #
    # Example output:
    #   "File is not checksummable - file does not exist at: /var/opt/gitlab/uploads/file.txt"
    #
    # For very long paths:
    #   "File is not checksummable - file does not exist at: very/long/path/that/was/truncated.txt"
    class MessageWithFilePath
      MAX_MESSAGE_LENGTH = 255

      def self.build(prefix:, file_path:)
        max_path_length = MAX_MESSAGE_LENGTH - prefix.length

        "#{prefix}#{truncated_path(file_path, max_path_length)}"
      end

      def self.truncated_path(path, max_length)
        return '(path unavailable)' if path.nil?
        return path if path.length <= max_length

        path[-max_length..]
      end
    end
  end
end
