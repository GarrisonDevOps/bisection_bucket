# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Repositories
        module BlobsTool
          extend ::Gitlab::Utils::Override

          override :excluded_paths
          def excluded_paths(project, paths)
            result = ::Ai::FileExclusionService.new(project).execute(paths)
            return [] unless result.success?

            result.payload.filter_map { |entry| entry[:path] if entry[:excluded] }
          end
        end
      end
    end
  end
end
