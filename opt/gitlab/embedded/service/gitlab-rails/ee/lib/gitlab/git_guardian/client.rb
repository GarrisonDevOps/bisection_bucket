# frozen_string_literal: true

module Gitlab
  module GitGuardian
    class Client
      include ActionView::Helpers::TextHelper

      DEFAULT_API_URL = 'https://api.gitguardian.com'
      MULTISCAN_PATH = '/v1/multiscan'
      TIMEOUT = 5.seconds
      BATCH_SIZE = 20
      FILENAME_LIMIT = 256
      NA = 'N/A'

      Error = Class.new(StandardError)
      ConfigError = Class.new(Error)
      RequestError = Class.new(Error)

      attr_reader :api_token, :multiscan_url

      def initialize(api_token, api_url: nil)
        raise ConfigError, 'Please check your integration configuration.' unless api_token.present?

        @api_token = api_token
        @multiscan_url = "#{(api_url.presence || DEFAULT_API_URL).chomp('/')}#{MULTISCAN_PATH}".freeze
      end

      def execute(blobs = [], repository_url = NA)
        threaded_batches = []
        blobs.each_slice(BATCH_SIZE).map.with_object([]) do |blobs_batch, _|
          threaded_batches << execute_batched_request(blobs_batch, repository_url)
        end

        threaded_batches.filter_map(&:value).flatten
      end

      private

      def execute_batched_request(blobs_batch, repository_url)
        Thread.new do
          params = blobs_batch.each_with_object([]) do |blob, all|
            # GitGuardian limits filename field to 256 characters.
            # That is why we only pass file name, which is sufficient for Git Guardian to perform its checks.
            # See: https://api.gitguardian.com/docs#operation/multiple_scan
            if blob.path.present?
              filename = File.basename(blob.path)
              limited_filename = limit_filename(filename)
            end

            unless can_be_jsonified?(blob.data)
              Gitlab::AppJsonLogger.warn(class: self.class.name,
                message: "Not processing data with filename '#{limited_filename}' as it cannot be JSONified")
              next
            end

            blob_params = { document: blob.data }
            blob_params[:filename] = limited_filename if limited_filename

            all << blob_params
          end

          if params.empty?
            Gitlab::AppJsonLogger.warn(class: self.class.name, message: "Nothing to process")
            nil
          else
            response = perform_request(params, repository_url)
            policy_breaks = process_response(response, blobs_batch)

            policy_breaks.presence
          end
        end
      end

      def limit_filename(filename)
        filename_size = filename.length
        over_limit = filename.length - FILENAME_LIMIT
        return filename if over_limit <= 0

        # We splice the filename to keep it under 256 characters
        # in a First-In-First-Out to keep the file extension
        # which is necessary to some GitGuardian policies checks
        filename[over_limit..filename_size]
      end

      def can_be_jsonified?(data)
        data.to_json
        true
      rescue JSON::GeneratorError
        false
      end

      def perform_request(params, repository_url)
        options = {
          headers: headers(repository_url),
          body: params.to_json,
          timeout: TIMEOUT
        }

        response = Gitlab::HTTP.post(multiscan_url, options)

        raise RequestError, "HTTP status code #{response.code}" unless response.success?

        response
      end

      def headers(repository_url)
        {
          'Content-Type': 'application/json',
          Authorization: "Token #{api_token}",
          'GGshield-Repository-URL': repository_url
        }
      end

      def process_response(response, blobs)
        parsed_response = Gitlab::Json::SafeParser.parse(response.body)
        raise Error, 'invalid response format' unless parsed_response.is_a?(Array)

        parsed_response.filter_map.with_index do |policy_break_for_file, blob_index|
          next if policy_break_for_file['policy_break_count'] == 0

          blob = blobs[blob_index]

          next unless blob

          formatted_errors_for_file(policy_break_for_file['policy_breaks'], blob)
        end
      rescue JSON::ParserError
        raise Error, 'invalid response format'
      end

      # Format the message with indentation to print it like:
      #
      # remote: GitLab: .env: 1 incident detected:
      # remote:
      # remote:  >> Filenames: .env
      # remote:     Validity: N/A
      # remote:     Known by GitGuardian: N/A
      # remote:     Incident URL: N/A
      # remote:     Violation: filename `.env` detected
      def formatted_errors_for_file(policy_breaks, blob)
        result = "#{blob.path}: #{pluralize(policy_breaks.size, 'incident')} detected:\n\n"

        error_output_for_file(policy_breaks, blob).each do |messages|
          result << " >> "
          result << messages.join("\n    ")
          result << "\n\n"
        end

        result
      end

      def error_output_for_file(policy_breaks, blob)
        policy_breaks.map do |policy_break|
          result = [
            "#{policy_break['policy']}: #{policy_break['type']}",
            "Validity: #{policy_break['validity']&.humanize || NA}",
            "Known by GitGuardian: #{Gitlab::Utils.boolean_to_yes_no(policy_break['known_secret'])}",
            "Incident URL: #{policy_break['incident_url'].presence || NA}"
          ]

          blob_lines = blob.lines

          policy_break['matches'].each do |violation_match|
            type, match = violation_match.values_at('type', 'match')
            result << "Violation: #{type} `#{match}` detected"

            next unless violation_match['line_start'].present?

            line_start = violation_match['line_start']
            line_end = violation_match['line_end'] || line_start

            (line_start..line_end).each do |line_number|
              # line_start field index origin is 1
              line = blob_lines[line_number - 1]

              next unless line && line.index(match)

              # Prefix the printed line with the line number and
              # print the match type underneath the matched value
              #
              # Violation: password `password` detected
              # 201 | url = 'http://user:password123456@hi.gitlab.com/hello.json'
              #                          |__password__|
              line_number_prefix = "#{line_number} | "
              result << "#{line_number_prefix}#{line}"

              index_start = line_number_prefix.size + line.index(match)
              result << "#{' ' * index_start}|#{type.center(match.size - 2, '_')}|"
            end
          end

          result
        end
      end
    end
  end
end
