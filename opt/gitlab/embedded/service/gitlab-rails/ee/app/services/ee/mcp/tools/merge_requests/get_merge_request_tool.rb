# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module MergeRequests
        module GetMergeRequestTool
          extend ::Gitlab::Utils::Override

          override :process_result
          def process_result(result)
            response = super
            return response if response[:isError]

            response = filter_excluded_diffs(response)
            filter_excluded_conflict_files(response)
          end

          private

          def filter_excluded_diffs(response)
            merge_request = response[:structuredContent]
            diffs = merge_request&.dig('diffs', 'nodes')
            return response if diffs.blank?

            project = excluded_diffs_project
            return response unless project

            excluded_paths = excluded_diff_paths(project, diffs)
            return response if excluded_paths.empty?

            merge_request['diffs']['nodes'] = diffs.reject do |diff|
              excluded_paths.include?(diff['newPath']) || excluded_paths.include?(diff['oldPath'])
            end

            content = [{ type: 'text', text: ::Gitlab::Json.dump(merge_request) }]
            ::Mcp::Tools::Base::Response.success(content, merge_request)
          end

          def filter_excluded_conflict_files(response)
            merge_request = response[:structuredContent]
            conflict_files = merge_request&.[]('conflictFiles')
            return response if conflict_files.blank?

            project = excluded_diffs_project
            return response unless project

            file_paths = conflict_files.filter_map { |f| [f['ourPath'], f['theirPath']] }.flatten.compact.uniq
            return response if file_paths.empty?

            result = ::Ai::FileExclusionService.new(project).execute(file_paths)
            return response unless result.success?

            excluded_paths = result.payload.filter_map { |file| file[:path] if file[:excluded] }.to_set
            return response if excluded_paths.empty?

            merge_request['conflictFiles'] = conflict_files.reject do |f|
              excluded_paths.include?(f['ourPath']) || excluded_paths.include?(f['theirPath'])
            end

            content = [{ type: 'text', text: ::Gitlab::Json.dump(merge_request) }]
            ::Mcp::Tools::Base::Response.success(content, merge_request)
          end

          def excluded_diffs_project
            full_path, _iid = resolve_target
            find_project(full_path)
          end

          def excluded_diff_paths(project, diffs)
            file_paths = diffs.filter_map { |diff| diff['newPath'] || diff['oldPath'] }.uniq
            return Set.new if file_paths.empty?

            result = ::Ai::FileExclusionService.new(project).execute(file_paths)
            return Set.new unless result.success?

            result.payload.filter_map { |file| file[:path] if file[:excluded] }.to_set
          end
        end
      end
    end
  end
end
