# frozen_string_literal: true

module Mcp
  module Tools
    module Jobs
      class GetJobService < Base::CustomService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        INCLUDES = %w[log artifacts].freeze
        MAX_BYTE_LIMIT = ::Gitlab::Ci::Trace::Stream::LIMIT_SIZE
        MIN_BYTE_OFFSET = 0
        LOG_ALIAS = 'get_job_log'
        NOT_FOUND = 'Job not found or inaccessible'
        LOG_FORBIDDEN = "Job log not accessible: you do not have permission to read this job's log."

        container_arguments project: :id

        register_version '0.1.0', {
          toolset: :ci,
          description: 'Get a CI/CD job in a GitLab project. Add include: log to also get the ' \
            "job's trace/log, which you can page through with byte_offset and byte_limit. " \
            'Use from: end with a small byte_limit to read only the tail of the log. ' \
            'Add include: artifacts to also list the artifacts the job produced (name, size, ' \
            'file type); read one with the get_artifact_file tool.',
          annotations: {
            title: 'Get job',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          input_schema: {
            type: 'object',
            properties: {
              id: {
                type: 'string',
                description: 'ID or full path of the project'
              },
              job_id: {
                type: 'integer',
                description: 'ID of the job'
              },
              include: {
                type: 'array',
                description: 'Facets to include alongside the job: log, artifacts, or both.',
                items: {
                  type: 'string',
                  enum: INCLUDES
                },
                maxItems: INCLUDES.size
              },
              from: {
                type: 'string',
                enum: %w[start end],
                description: 'Reads from the start of the log unless set to end. ' \
                  'Cannot combine end with byte_offset. Only applies when include contains log.'
              },
              byte_offset: {
                type: 'integer',
                minimum: MIN_BYTE_OFFSET,
                description: "Byte offset to start reading the job's log from. Only applies when include contains log."
              },
              byte_limit: {
                type: 'integer',
                minimum: 1,
                maximum: MAX_BYTE_LIMIT,
                description: "Maximum number of bytes of the job's log to return; maximum is #{MAX_BYTE_LIMIT}. " \
                  "Only applies when include contains log."
              }
            },
            required: %w[id job_id]
          }
        }

        override :tool_aliases
        def self.tool_aliases
          # get_job_log only ever returned the log, with no `include` param. Calls made under
          # that name are treated as an implicit `include: log` so they keep returning it.
          [LOG_ALIAS]
        end

        override :authorization_error_message
        def authorization_error_message
          log_forbidden? ? LOG_FORBIDDEN : NOT_FOUND
        end

        protected

        def auth_ability
          include_log? ? :read_build_trace : :read_build
        end

        def granular_permissions
          [:read_job]
        end

        def auth_target(params)
          @arguments = params[:arguments] || {}
          @invoked_as = params[:name]

          job || raise(ResourceNotFoundError, NOT_FOUND)
        end

        def perform_default(arguments = {})
          @arguments = arguments || {}

          data = job_data
          data[:log] = log_facet if include_log?
          data[:artifacts] = artifacts_facet if include_artifacts?

          formatted_content = [{ type: 'text', text: Gitlab::Json.generate(data) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        private

        attr_reader :arguments

        def job
          project = find_project!(arguments[:id])

          # The caller gives us a job ID only, so there is no partition_id to scope by. Same
          # lookup as `find_build!` in lib/api/helpers.rb, which backs GET /projects/:id/jobs/:job_id.
          # rubocop:disable Database/AvoidUnpartitionedCiRelations -- no partition key available
          project.builds.find_by_id(arguments[:job_id])
          # rubocop:enable Database/AvoidUnpartitionedCiRelations
        end
        strong_memoize_attr :job

        # A caller who can read the job already knows it exists, so naming the real reason the
        # log is off limits leaks nothing. The REST trace endpoint answers 403 here too.
        def log_forbidden?
          include_log? && ::Ability.allowed?(current_user, :read_build, job)
        end

        def include_log?
          @invoked_as == LOG_ALIAS || Array(arguments[:include]).include?('log')
        end

        def include_artifacts?
          Array(arguments[:include]).include?('artifacts')
        end

        def job_data
          {
            id: job.id,
            name: job.name,
            status: job.status,
            stage: job.stage,
            allow_failure: job.allow_failure,
            web_url: ::Gitlab::Routing.url_helpers.project_job_url(job.project, job)
          }
        end

        # Bounded without pagination: a job stores at most one artifact per file type.
        def artifacts_facet
          job.job_artifacts.map do |artifact|
            {
              id: artifact.id,
              name: artifact.filename,
              size: artifact.size,
              file_type: artifact.file_type,
              expire_at: artifact.expire_at,
              expired: artifact.expired?
            }
          end
        end

        def log_facet
          from_end = arguments[:from] == 'end'
          if from_end && arguments.key?(:byte_offset)
            raise ArgumentError, 'byte_offset cannot be combined with from: end'
          end

          byte_limit = arguments[:byte_limit] || MAX_BYTE_LIMIT

          total_bytes, byte_offset, content = job.trace.read do |stream|
            total = stream.size || 0
            offset = from_end ? [total - byte_limit, 0].max : arguments[:byte_offset] || MIN_BYTE_OFFSET

            [total, offset, stream.raw_range(byte_offset: offset, byte_limit: byte_limit).to_s]
          end

          returned_start = [byte_offset, total_bytes].min
          returned_end = returned_start + content.bytesize
          truncated = returned_end < total_bytes

          system_instruction = if from_end && returned_start > 0
                                 previous_start = [returned_start - byte_limit, 0].max
                                 "Read earlier log bytes with {\"from\": \"start\", " \
                                   "\"byte_offset\": #{previous_start}, " \
                                   "\"byte_limit\": #{returned_start - previous_start}}. " \
                                   'To keep reading backwards, lower byte_offset by byte_limit each call, down to 0.'
                               elsif truncated
                                 "Log truncated. Remaining: #{total_bytes - returned_end} bytes. " \
                                   "Call again with {\"byte_offset\": #{returned_end}}."
                               end

          {
            metadata: {
              total_bytes: total_bytes,
              returned: { start: returned_start, end: returned_end },
              truncated: truncated
            },
            # A byte window can split a multi-byte character, so scrub before the response is
            # serialized to JSON, which rejects invalid UTF-8.
            content: content.scrub,
            system_instruction: system_instruction
          }.compact
        end
      end
    end
  end
end
