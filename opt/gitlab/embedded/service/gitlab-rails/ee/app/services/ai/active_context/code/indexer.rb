# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class Indexer < IndexerBase
        def self.run!(active_context_repository, &block)
          new(active_context_repository).run(&block)
        end

        def run(&block)
          raise Error, 'Adapter not set' unless adapter

          # determine the commit-related values at the beginning of indexing
          # to ensure we are logging the correct values
          determine_shas_and_force_reindex_flag

          response_processor = IndexerResponseModifier.new(&block)
          stderr_output = []

          status = log_duration('Run indexer') do
            Gitlab::Popen.popen_with_streaming(command, nil, environment_variables) do |stream_type, line|
              case stream_type
              when :stdout
                response_processor.process_line(line)
              when :stderr
                stderr_output << line
              end
            end
          end

          if status.success?
            log_info('Indexer successful', status: status.exitstatus)
            return to_sha
          end

          if status.signaled? && deploy_signal?(status.termsig)
            log_info('Indexer interrupted', termsig: status.termsig)
            raise Interrupted, "Indexer interrupted by signal #{status.termsig}"
          end

          # A signal we do not treat as an interruption (e.g. SIGKILL) leaves exitstatus nil.
          # Fall back to the signal number in the message, so it still shows a cause.
          status_description = status.exitstatus || "signal #{status.termsig}"

          log_error(
            "Indexer failed",
            status: status.exitstatus,
            error_details: stderr_output.join
          )
          raise Error, "Indexer failed with status: #{status_description} and error: #{stderr_output.join}"
        end

        private

        attr_reader :from_sha, :to_sha, :force_reindex

        # Gitlab::SidekiqSignals forwards these same signals to the process group on deploy.
        def deploy_signal?(termsig)
          Gitlab::SidekiqSignals::REPLACE_SIGNALS.include?(Signal.signame(termsig))
        end

        def determine_shas_and_force_reindex_flag
          @to_sha = project_repository.commit&.id
          raise Error, "Project repository commit not found" unless @to_sha

          if force_push?
            @from_sha = project_repository.empty_tree_id
            @force_reindex = true
            return
          end

          @from_sha = last_indexed_commit
          @force_reindex = false
        end

        def force_push?
          if last_indexed_commit.blank? ||
              Gitlab::Git.blank_ref?(last_indexed_commit) ||
              last_indexed_commit == project_repository.empty_tree_id
            return false
          end

          !git_repository_contains_last_indexed_commit?
        end

        def last_indexed_commit
          @last_indexed_commit ||= active_context_repository.last_commit
        end

        def git_repository_contains_last_indexed_commit?
          log_duration('git_repository_contains_last_indexed_commit?') do
            last_indexed_commit.present? && project_repository.commit(last_indexed_commit).present?
          end
        end

        def options
          base_options.merge(
            {
              from_sha: from_sha,
              to_sha: to_sha,
              force_reindex: force_reindex,
              gitaly_config: gitaly_config,
              chunk_strategy: collection_class.collection_record.chunk_strategy,
              chunk_size: collection_class.collection_record.chunk_strategy_size
            }
          )
        end

        def gitaly_config
          {
            storage: project.repository_storage,
            relative_path: project_repository.relative_path,
            project_path: project.full_path
          }.merge(Gitlab::GitalyClient.connection_data(project.repository_storage))
        end

        def build_log_payload(message, extra_params = {})
          super(message, extra_params.merge(from_sha: from_sha, to_sha: to_sha))
        end
      end
    end
  end
end
