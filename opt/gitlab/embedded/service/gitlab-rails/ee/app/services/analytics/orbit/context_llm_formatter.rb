# frozen_string_literal: true

module Analytics
  module Orbit
    class ContextLlmFormatter
      RESOLVED_STATES = { true => ' [resolved]', false => ' [unresolved]' }.freeze
      IID_SIGILS = { 'MergeRequest' => '!', 'WorkItem' => '#' }.freeze

      def initialize(context)
        @context = context
      end

      def execute
        lines = ["orbit_context version=#{context[:version]} entities=#{context[:entities].size}"]
        context[:entities].each { |entity| lines.concat(format_entity(entity)) }
        lines.join("\n") << "\n"
      end

      private

      attr_reader :context

      def format_entity(entity)
        unless entity[:found]
          return ["- #{format_value(entity[:token])} found=false error=#{entity.dig(:error, :code)}"]
        end

        summary = entity[:summary]
        ref = reference(entity[:type], summary.merge(id: entity[:id])) || entity[:resolved_token]
        lines = ["- #{ref} id=#{entity[:id]} found=true"]
        scalar_fields(summary).each { |key, value| lines << "  #{key}=#{format_value(value)}" }
        append_truncated(lines, summary[:truncated], '  ')
        append_users(lines, 'author', summary[:author] && [summary[:author]])
        append_users(lines, 'reviewers', summary[:reviewers])
        append_users(lines, 'assignees', summary[:assignees])
        append_labels(lines, summary[:labels])
        append_milestone(lines, summary[:milestone])
        append_all_links(lines, summary)
        lines.concat(format_expansion(entity[:expansion]))
        append_failed_tests(lines, summary[:failed_tests], '  ')
        append_block(lines, 'log', summary[:log])
        append_block(lines, 'description', summary[:description])
        append_changed_files(lines, summary[:changed_files])
        append_jobs(lines, summary[:jobs])
        append_failed_jobs(lines, summary[:failed_jobs])
        append_discussions(lines, summary[:discussions])
        lines
      end

      def scalar_fields(summary)
        summary.slice(
          :title, :state, :work_item_type, :namespace_path, :project_path, :web_url, :source_branch,
          :target_branch, :head_pipeline_status, :merge_commit_sha, :name, :status, :stage, :failure_reason,
          :allow_failure, :ref, :sha, :pipeline_id, :pipeline_status, :source, :default_branch, :author_name,
          :authored_date
        ).compact
      end

      def format_expansion(expansion)
        return [] unless expansion
        return ["  graph_error=#{expansion.dig(:error, :code)}"] if expansion[:error]

        graph = expansion[:result].to_s.chomp
        return [] unless graph.match?(/^nodes\b/)

        ['  graph:', *graph.lines(chomp: true).map { |line| "    #{line}" }]
      end

      def append_truncated(lines, names, indent)
        lines << "#{indent}truncated=#{names.join(',')}" if names.present?
      end

      def append_users(lines, key, users)
        return if users.blank?

        values = users.map { |user| "#{user[:username]} (#{user[:name]}, id=#{user[:id]})" }
        lines << "  #{key}=#{format_value(values.join(', '))}"
      end

      def append_labels(lines, labels)
        lines << "  labels=#{format_value(labels.join(', '))}" if labels.present?
      end

      def append_milestone(lines, milestone)
        lines << "  milestone=#{format_value("#{milestone[:title]} (id=#{milestone[:id]})")}" if milestone
      end

      def append_all_links(lines, summary)
        append_links(lines, 'linked_issues', summary[:linked_issues])
        append_links(lines, 'linked_merge_requests', summary[:linked_merge_requests])
        append_links(lines, 'merge_request', [summary[:merge_request]].compact)
        append_links(lines, 'merge_requests', summary[:merge_requests])
      end

      def append_links(lines, key, links)
        return if links.blank?

        values = links.map { |link| "#{reference(link[:type], link) || link[:token]} #{link[:title]}" }
        lines << "  #{key}=#{format_value(values.join('; '))}"
      end

      # Emits only forms that `ContextToken.parse` accepts, so agents can pass them back as tokens.
      def reference(type, item)
        return "#{type}[#{item[:id]}]" if %w[Job Pipeline].include?(type) && item[:id]
        return "#{item[:project_path]}@#{item[:id]}" if %w[Branch Commit].include?(type) && item[:project_path]

        path = item[:project_path] || item[:namespace_path]
        sigil = IID_SIGILS[type]
        "#{path}#{sigil}#{item[:iid]}" if path && sigil && item[:iid]
      end

      def append_block(lines, key, text, indent = '    ')
        return if text.blank?

        lines << "  #{key}:" unless key.nil?
        text.to_s.each_line { |line| lines << "#{indent}#{line.rstrip}" }
      end

      def append_changed_files(lines, files)
        return if files.blank?

        lines << "  changed_files[#{files.size}]:"
        files.each do |file|
          renamed = file[:old_path] ? " (from #{file[:old_path]})" : ''
          changed = file[:lines].present? ? " @ #{file[:lines].join(', ')}" : ''
          lines << "    #{file[:status]} #{file[:path]}#{renamed}#{changed}"
          append_block(lines, nil, file[:diff], '      | ')
        end
      end

      def append_jobs(lines, jobs)
        return if jobs.blank?

        lines << "  jobs[#{jobs.size}]:"
        jobs.each do |job|
          flags = [job[:stage], job[:status], ('allowed to fail' if job[:allow_failure])].compact.join(', ')
          lines << "    #{job[:name]} (#{flags})"
        end
      end

      def append_failed_jobs(lines, jobs)
        return if jobs.blank?

        lines << "  failed_jobs[#{jobs.size}]:"
        jobs.each do |job|
          flags = [job[:stage], job[:failure_reason], ('allowed to fail' if job[:allow_failure])].compact.join(', ')
          lines << "    #{job[:name]} (#{flags}) #{job[:web_url]}"
          append_truncated(lines, job[:truncated], '      ')
          append_failed_tests(lines, job[:failed_tests], '      ')
          append_block(lines, nil, job[:log], '      | ')
        end
      end

      def append_failed_tests(lines, tests, indent)
        return if tests.blank?

        lines << "#{indent}failed_tests[#{tests.size}]:"
        tests.each do |test|
          location = test[:file] ? " #{test[:file]}" : ''
          lines << "#{indent}  #{[test[:classname], test[:name]].compact.join(' ')}#{location}"
          append_block(lines, nil, test[:output], "#{indent}    ")
        end
      end

      def append_discussions(lines, notes)
        return if notes.blank?

        lines << "  discussions[#{notes.size}]:"
        notes.each do |note|
          state = RESOLVED_STATES.fetch(note[:resolved], '')
          location = note[:path] ? " #{[note[:path], note[:line]].compact.join(':')}" : ''
          lines << "    @#{note[:author]} #{note[:created_at]}#{state}#{location}:"
          append_block(lines, nil, note[:body], '      ')
        end
      end

      def format_value(value)
        ::Gitlab::Json.generate(value.to_s)
      end
    end
  end
end
