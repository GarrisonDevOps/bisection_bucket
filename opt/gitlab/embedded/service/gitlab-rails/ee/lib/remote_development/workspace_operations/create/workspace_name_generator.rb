# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceNameGenerator
        RANDOM_STRING_LENGTH = 5
        WORKSPACE_NAME_MAX_LENGTH = 34

        # @return [String]
        def self.generate
          max_retries = 50
          workspace_name = ""

          max_retries.times do |_|
            workspace_name = [
              FFaker::Food.fruit,
              FFaker::AnimalUS.common_name,
              FFaker::Color.name
            ].map(&:downcase)
             .map { |name| name.parameterize(separator: "") }
             .join("-")

            unless workspace_name.length >= WORKSPACE_NAME_MAX_LENGTH ||
                RemoteDevelopment::Workspace.by_names(workspace_name).exists?
              return workspace_name
            end
          end

          random_string = SecureRandom.alphanumeric(RANDOM_STRING_LENGTH).downcase
          workspace_name[0..WORKSPACE_NAME_MAX_LENGTH - 1 - RANDOM_STRING_LENGTH] << random_string
        end
      end
    end
  end
end
