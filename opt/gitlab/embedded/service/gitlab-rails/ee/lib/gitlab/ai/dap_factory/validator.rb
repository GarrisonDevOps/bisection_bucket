# frozen_string_literal: true

module Gitlab
  module Ai
    module DapFactory
      # The one ruleset for `.gitlab-dap-factory.yml`, shared by Sync, the Factory Editor and merge request
      # validation. Without a project only the shape is checked; with one, statuses and flows must exist
      # in the project.
      class Validator
        MAX_BYTES = 64.kilobytes
        MAX_UNKNOWN_KEYS = 20
        # One byte over the limit lets a huge file be rejected without loading it.
        READ_LIMIT = MAX_BYTES + 1

        TOP_LEVEL_KEYS = %w[factory status stages review].freeze
        STAGE_KEYS = %w[start exit flow mark_merge_requests_ready].freeze
        FOUNDATIONAL_REFERENCE = %r{\A[a-z0-9_]+/(v\d+|experimental)\z}
        MAX_STATUS_LENGTH = 32

        # `path` is a dotted path into the file, such as `stages.build.flow`, so an editor can show
        # the message next to the field it is about. It is nil for problems with the whole file.
        Message = Data.define(:path, :code, :message)

        Result = Data.define(:configuration, :errors, :warnings) do
          def valid?
            errors.empty?
          end
        end

        def initialize(content:, project: nil)
          @content = content.to_s
          @project = project
          @errors = []
          @warnings = []
        end

        def execute
          return finish if too_large?

          data = parse
          return finish if data.nil?

          warn_unknown_keys(nil, data, TOP_LEVEL_KEYS)
          factory_name = read_factory_name(data['factory'])
          statuses = read_statuses(data['status'])
          settings = read_stage_settings(data['stages'])
          stages = read_stages(statuses, settings) if statuses && settings
          review = read_review(data)
          stages = check_stages(stages) if stages

          configuration = Configuration.new(factory_name: factory_name, stages: stages, review: review) if
            errors.empty?

          finish(configuration)
        end

        private

        attr_reader :content, :project, :errors, :warnings

        def finish(configuration = nil)
          Result.new(configuration: configuration, errors: errors.freeze, warnings: warnings.freeze)
        end

        def error(path, code, message)
          errors << Message.new(path: path, code: code, message: message)
          nil
        end

        def warning(path, code, message)
          warnings << Message.new(path: path, code: code, message: message)
        end

        def too_large?
          return false if content.bytesize <= MAX_BYTES

          error(nil, :too_large, format(s_('DapSoftwareFactory|The file must be %{size} or smaller.'),
            size: ActiveSupport::NumberHelper.number_to_human_size(MAX_BYTES)))
          true
        end

        # The same loader the fix loop uses on this file, so both read it the same way.
        def parse
          loader = ::Gitlab::Config::Loader::Yaml.new(content)
          return error(nil, :empty, s_('DapSoftwareFactory|The file is empty.')) if loader.blank?

          loader.load_raw!
        rescue ::Gitlab::Config::Loader::Yaml::NotHashError
          error(nil, :not_a_mapping, s_('DapSoftwareFactory|The file must be a mapping.'))
        rescue ::Gitlab::Config::Loader::Yaml::DataTooLargeError
          error(nil, :too_large, s_('DapSoftwareFactory|The file has too much content to be read.'))
        rescue ::Gitlab::Config::Loader::FormatError => e
          error(nil, :invalid_yaml, format(s_('DapSoftwareFactory|The file is not valid YAML: %{problem}.'),
            problem: e.message.delete_prefix('(<unknown>): ')))
        end

        def warn_unknown_keys(path, hash, known)
          unknown = key_names(hash) - known

          unknown.first(MAX_UNKNOWN_KEYS).each do |key|
            key_path = [path, key].compact.join('.')
            warning(key_path, :unknown_key,
              format(s_('DapSoftwareFactory|%{key} is not a known setting and is ignored.'), key: key_path))
          end

          omitted = unknown.size - MAX_UNKNOWN_KEYS
          return unless omitted > 0

          warning(path, :unknown_keys_omitted,
            format(ns_('DapSoftwareFactory|%{count} more unknown setting is ignored.',
              'DapSoftwareFactory|%{count} more unknown settings are ignored.', omitted), count: omitted))
        end

        # The loader permits symbol keys, which no lookup here matches, so `:status` is reported rather than ignored.
        def key_names(hash)
          hash.keys.map { |key| key.is_a?(String) ? key : key.inspect }
        end

        def read_factory_name(value)
          return if value.nil?
          return value.to_s if value.is_a?(String) || value.is_a?(Numeric)

          error('factory', :invalid_factory, s_('DapSoftwareFactory|The factory name must be text.'))
        end

        # The flows of the factory read this block too, to know which status to set.
        def read_statuses(value)
          return {} if value.nil?

          unless value.is_a?(Hash)
            return error('status', :invalid_status_block,
              s_('DapSoftwareFactory|The status block must be a mapping from stage to work item status.'))
          end

          warn_unknown_keys('status', value, Configuration::STATUS_KEYS)

          # A rejected status is kept as nil, so the other stages are still checked.
          Configuration::STAGES.select { |key| value.key?(key) }.index_with do |key|
            read_status("status.#{key}", value[key])
          end
        end

        def read_stage_settings(value)
          return {} if value.nil?

          unless value.is_a?(Hash)
            return error('stages', :invalid_stages, s_('DapSoftwareFactory|The stages block must be a mapping.'))
          end

          unknown = key_names(value) - Configuration::STAGES
          unknown.first(MAX_UNKNOWN_KEYS).each do |key|
            error("stages.#{key}", :unknown_stage,
              format(s_('DapSoftwareFactory|%{key} is not a Software Factory stage. The stages are: %{stages}.'),
                key: key, stages: Configuration::STAGES.join(', ')))
          end

          if unknown.size > MAX_UNKNOWN_KEYS
            omitted = unknown.size - MAX_UNKNOWN_KEYS
            error('stages', :unknown_stages_omitted,
              format(ns_('DapSoftwareFactory|%{count} more key is not a Software Factory stage.',
                'DapSoftwareFactory|%{count} more keys are not Software Factory stages.', omitted), count: omitted))
          end

          Configuration::STAGES.select { |key| value.key?(key) }.index_with do |key|
            read_settings(key, value[key])
          end
        end

        def read_settings(key, value)
          path = "stages.#{key}"

          unless value.is_a?(Hash)
            return error(path, :invalid_stage,
              format(s_('DapSoftwareFactory|%{stage} must be a mapping with start, exit and flow. ' \
                'To skip a stage, remove it from status.'), stage: key))
          end

          warn_unknown_keys(path, value, STAGE_KEYS)
          value
        end

        # A stage that could not be read is nil in the result.
        def read_stages(statuses, settings)
          Configuration::STAGES.map do |key|
            if statuses.key?(key)
              next if settings.key?(key) && settings[key].nil?

              next build_stage(key, statuses[key], settings[key] || {})
            end

            next Configuration::Stage.skipped(key) unless settings.key?(key)

            error("stages.#{key}", :stage_without_status,
              format(s_('DapSoftwareFactory|%{stage} has settings, but no status. Add %{status}, ' \
                'or remove %{stages}.'), stage: key, status: "status.#{key}", stages: "stages.#{key}"))
          end
        end

        # Each stage is checked on its own, so one push reports every mistake. Only the checks that need
        # the whole file wait until every stage reads cleanly.
        def check_stages(stages)
          built = stages.compact
          check_project_statuses(built) if project
          check_flows(built) if project
          return stages unless stages.all? { |stage| stage && (stage.skipped? || stage.status) }

          check_routing(stages)
          check_duplicate_statuses(stages)
          warn_chaining_off(stages) if project
          project ? with_project_status_names(stages) : stages
        end

        def build_stage(key, status, value)
          path = "stages.#{key}"
          start_mode = read_mode("#{path}.start", value['start'])
          exit_mode = read_mode("#{path}.exit", value['exit'])
          flow = read_flow("#{path}.flow", value['flow'])
          ready = read_ready("#{path}.mark_merge_requests_ready", value['mark_merge_requests_ready'])

          return if [start_mode, exit_mode].any?(&:nil?) || flow == :invalid || ready == :invalid

          stage = Configuration::Stage.new(key: key, skipped: false, status: status, start_mode: start_mode,
            exit_mode: exit_mode, flow: flow, mark_merge_requests_ready: ready)

          check_stage(path, stage) ? stage : nil
        end

        def read_status(path, value)
          value = value.strip if value.is_a?(String)
          return value if value.is_a?(String) && value.present? && value.length <= MAX_STATUS_LENGTH

          error(path, :missing_status, s_('DapSoftwareFactory|The status must be the name of a work item status.'))
        end

        def read_mode(path, value)
          return Configuration::MANUAL if value.nil?
          return value if Configuration::MODES.include?(value)

          setting = path.split('.').last
          error(path, :"invalid_#{setting}",
            format(s_('DapSoftwareFactory|%{setting} must be automated or manual.'), setting: setting))
        end

        def read_flow(path, value)
          return if value.nil?
          return value if value.is_a?(Integer) && value > 0

          value = value.strip if value.is_a?(String)
          return value.to_i if value.is_a?(String) && value.match?(/\A[1-9]\d*\z/)
          return value if value.is_a?(String) && value.match?(FOUNDATIONAL_REFERENCE)

          error(path, :invalid_flow,
            s_('DapSoftwareFactory|The flow must be the ID of a flow in the AI Catalog, or the reference of a ' \
              'foundational flow such as developer/v1.'))
          :invalid
        end

        def read_ready(path, value)
          return false if value.nil?
          return value if [true, false].include?(value)

          error(path, :invalid_mark_merge_requests_ready,
            s_('DapSoftwareFactory|The mark_merge_requests_ready setting must be true or false.'))
          :invalid
        end

        def check_stage(path, stage)
          before = errors.size

          check_start_and_exit(path, stage)
          check_merge_request_driven(path, stage) if stage.merge_request_driven?
          check_flow(path, stage)

          errors.size == before
        end

        def check_start_and_exit(path, stage)
          if !stage.automated_start? && stage.automated_exit?
            error("#{path}.exit", :automated_exit_needs_automated_start,
              s_('DapSoftwareFactory|The exit can only be automated when the start is automated, because only a ' \
                'flow that the stage started can move the work item on.'))
          end

          return unless stage.mark_merge_requests_ready && !stage.automated_exit?

          error("#{path}.mark_merge_requests_ready", :ready_needs_automated_exit,
            s_('DapSoftwareFactory|Merge requests can only be marked ready when the exit is automated.'))
        end

        def check_merge_request_driven(path, stage)
          return unless stage.automated_exit?

          error("#{path}.exit", :automated_exit_not_supported,
            format(s_('DapSoftwareFactory|%{stage} exit must be manual. A person moves the work item on after the ' \
              'review.'), stage: stage_name(stage)))
        end

        def check_flow(path, stage)
          if stage.automated_start? && stage.flow.nil?
            error("#{path}.flow", :missing_flow,
              s_('DapSoftwareFactory|A flow is required when the start is automated.'))
          elsif !stage.automated_start? && stage.flow
            error("#{path}.flow", :flow_needs_automated_start,
              s_('DapSoftwareFactory|A flow can only be set when the start is automated.'))
          end
        end

        def check_routing(stages)
          configuration = Configuration.new(factory_name: nil, stages: stages, review: nil)

          stages.select(&:automated_exit?).each do |stage|
            next if configuration.next_stage_after(stage.key)

            error("stages.#{stage.key}.exit", :no_next_stage,
              format(s_('DapSoftwareFactory|%{stage} exit cannot be automated, because no stage after it is active.'),
                stage: stage_name(stage)))
          end
        end

        # Stages can share a status, except a stage whose status starts its flow: the status must say which
        # stage the work item is in, so the change starts exactly one flow.
        def check_duplicate_statuses(stages)
          active = stages.reject(&:skipped?)

          active.group_by { |stage| stage.status.downcase }.each_value do |sharing|
            next if sharing.one? || sharing.none?(&:status_triggered?)

            names = sharing.map { |stage| stage_name(stage) }.to_sentence
            sharing.each do |stage|
              error("status.#{stage.key}", :duplicate_status,
                format(s_('DapSoftwareFactory|%{stages} cannot share the status "%{status}", because it starts ' \
                  'a flow. A stage that starts on a status needs its own status.'),
                  stages: names, status: stage.status))
            end
          end
        end

        def check_project_statuses(stages)
          stages.each do |stage|
            next if stage.skipped? || stage.status.nil? || project_status_names.key?(stage.status.downcase)

            error("status.#{stage.key}", :unknown_status,
              format(s_('DapSoftwareFactory|"%{status}" is not a work item status in this project.'),
                status: stage.status))
          end
        end

        def stage_name(stage)
          stage.key.capitalize
        end

        def project_status_names
          @project_status_names ||= project.root_ancestor.statuses.to_h { |status| [status.name.downcase, status.name] }
        end

        # Matching is case-insensitive here, but triggers compare status names exactly, so Sync must use the
        # project's own spelling.
        def with_project_status_names(stages)
          stages.map do |stage|
            name = !stage.skipped? && project_status_names[stage.status.downcase]
            name ? Configuration::Stage.new(**stage.to_h, status: name) : stage
          end
        end

        def check_flows(stages)
          referenced = stages.filter_map(&:flow).uniq
          return if referenced.empty?

          enabled_items = enabled_flow_items(referenced)

          stages.select(&:flow).each do |stage|
            item = enabled_items[stage.flow]
            problem = flow_problem(item)
            next error("stages.#{stage.key}.flow", problem.first, format(problem.last, flow: stage.flow)) if problem

            warn_fix_loop_not_applied(stage, item) if stage.merge_request_driven?
          end
        end

        # One answer for missing, invisible and not enabled, so merge request content cannot probe private items.
        def enabled_flow_items(references)
          ids, flow_references = references.partition { |reference| reference.is_a?(Integer) }
          items = ::Ai::Catalog::Item.not_deleted.id_in(ids)
            .or(::Ai::Catalog::Item.not_deleted.with_foundational_flow_reference(flow_references)).index_by(&:id)
          enabled_ids = ::Ai::Catalog::ItemConsumer.for_projects(project).by_enabled(true).for_item(items.keys)
            .pluck_item_ids(items.size)

          items.slice(*enabled_ids).each_value.with_object({}) do |item, found|
            reference = item.foundational_flow_reference
            found[item.id] = item if ids.include?(item.id)
            found[reference] = item if flow_references.include?(reference)
          end
        end

        # On-finish settings, and a fix run that a verdict of Duo Code Review starts, both chain from the
        # session before them.
        def warn_chaining_off(stages)
          return if ::Feature.enabled?(:ai_flow_trigger_chaining, project.root_ancestor)

          stages.select(&:automated_exit?).each do |stage|
            warning("stages.#{stage.key}.exit", :chaining_off,
              s_('DapSoftwareFactory|Flow chaining is off for this group, so the work item does not move to the ' \
                'next status when the flow finishes.'))
          end

          review = stages.find(&:merge_request_driven?)
          return unless review.triggered?

          warning("stages.#{review.key}.start", :chaining_off,
            s_('DapSoftwareFactory|Flow chaining is off for this group, so a request for changes by ' \
              'GitLab Duo Code Review starts no fix run.'))
        end

        def warn_fix_loop_not_applied(stage, item)
          return if item.foundational_flow_reference == ::Ai::FlowTriggers::FixLoop.developer_reference

          warning("stages.#{stage.key}.flow", :fix_loop_not_applied,
            format(s_('DapSoftwareFactory|%{flow} is not GitLab Duo Developer, so the fix loop does not apply. ' \
              'The flow runs on every request for changes, and review.max_fix_runs does not limit it.'),
              flow: stage.flow))
        end

        def flow_problem(item)
          unless item
            return [:flow_not_enabled,
              s_('DapSoftwareFactory|%{flow} is not a flow enabled in this project. Enable it in the AI Catalog ' \
                'first.')]
          end

          return if item.flow? || item.third_party_flow?

          [:not_a_flow, s_('DapSoftwareFactory|%{flow} is enabled in this project, but it is not a flow.')]
        end

        # The fix loop reads the `review` key itself, so its own reader decides what is valid.
        def read_review(data)
          review = ::Ai::FlowTriggers::FixLoop::Config.new(data.key?('review') ? content : nil)
          review.errors.each { |message| error('review', :invalid_review, message) }
          review
        end
      end
    end
  end
end
