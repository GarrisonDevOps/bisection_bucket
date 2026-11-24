# frozen_string_literal: true

module Langsmith
  # This is a Ruby client for Langsmith API.
  # The interfaces are orthogonal to https://api.smith.langchain.com/docs#/run.
  class Client
    RETRIES_LIMIT = 3

    # https://api.smith.langchain.com/docs#/run/create_run_api_v1_runs_post
    def post_run(run_id:, name:, run_type:, inputs:, parent_id: nil, tags: [], extra: {})
      data = {
        id: run_id,
        name: name,
        run_type: run_type,
        inputs: inputs,
        start_time: current_time,
        session_name: project_name,
        tags: tags,
        extra: extra
      }

      data[:parent_run_id] = parent_id if parent_id

      with_retry do
        Gitlab::HTTP.post(
          "#{endpoint}/runs",
          headers: headers,
          body: data.to_json
        )
      end
    end

    # https://api.smith.langchain.com/docs#/run/update_run_api_v1_runs__run_id__patch
    def patch_run(run_id:, outputs: {}, events: [], error: "")
      data = {
        outputs: outputs,
        end_time: current_time,
        error: error,
        events: events
      }

      with_retry do
        Gitlab::HTTP.patch(
          "#{endpoint}/runs/#{run_id}",
          headers: headers,
          body: data.to_json
        )
      end
    end

    def self.enabled?
      ENV['LANGCHAIN_TRACING_V2'] == 'true'
    end

    private

    def with_retry
      retries = 0

      begin
        yield
      rescue Net::OpenTimeout => ex
        raise ex if retries >= RETRIES_LIMIT

        retries += 1
        retry
      end
    end

    def headers
      { "x-api-key": api_key }
    end

    def api_key
      ENV['LANGCHAIN_API_KEY']
    end

    def endpoint
      ENV['LANGCHAIN_ENDPOINT'] || 'https://api.smith.langchain.com'
    end

    def project_name
      ENV['LANGCHAIN_PROJECT'] || 'default'
    end

    def current_time
      Time.current.iso8601(3)
    end
  end
end
