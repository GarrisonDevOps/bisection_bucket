# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Repositories
        module GetRepositoryFileTool
          extend ::Gitlab::Utils::Override

          override :file_excluded?
          def file_excluded?(project, path)
            result = ::Ai::FileExclusionService.new(project).execute([path])
            return false unless result.success?

            result.payload.any? { |entry| entry[:excluded] }
          end
        end
      end
    end
  end
end
