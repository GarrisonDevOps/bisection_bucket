# frozen_string_literal: true

module Search
  module Zoekt
    module ResponseParser
      # Extract project_id from Zoekt file response.
      # Prefers RepositoryID (legacy format) but falls back to Repository
      # when RepositoryID is missing or zero.
      #
      # Background: Both RepositoryID and Repository fields are present in Zoekt
      # responses. For projects with IDs larger than uint32 (4,294,967,295), the
      # Zoekt indexer's SafeConvertUint64ToUint32 sets RepositoryID to 0, so we
      # must use the Repository field from metadata instead.
      #
      # @param file [Hash] Zoekt file response hash
      # @return [Integer] The project ID
      def extract_project_id(file)
        repository_id = file[:RepositoryID].to_i
        return repository_id if repository_id > 0

        file[:Repository].to_i
      end
    end
  end
end
