# frozen_string_literal: true

def require_env_var(var_name, default = nil)
  value = ENV[var_name] || default
  raise "Environment variable #{var_name} not set" if value.nil?

  value
end

namespace :gitlab do
  namespace :duo_chat do
    desc 'GitLab | DuoChat | Generate completions for the given context'
    task :completions, [:root_group_path, :user_id] => :environment do |_, args|
      dataset_dir = require_env_var('AIEF_DATASET')
      output_dir = require_env_var('AIEF_OUTPUT')
      error_limit = require_env_var('ERROR_LIMIT', 5).to_i

      unless ::Gitlab.dev_or_test_env?
        raise <<~ERROR_MESSAGE.strip
        This task can be only ran locally.
        ERROR_MESSAGE
      end

      unless args[:root_group_path]
        raise <<~ERROR_MESSAGE.strip
        Group not provided.
        ERROR_MESSAGE
      end

      unless args[:user_id]
        raise <<~ERROR_MESSAGE.strip
        User not provided.
        ERROR_MESSAGE
      end

      duo_chat = ::Gitlab::Duo::Chat::Request.new(args.to_h)
      reader = ::Gitlab::Duo::Chat::DatasetReader.new(dataset_dir)
      writer = ::Gitlab::Duo::Chat::DatasetWriter.new(output_dir)

      progressbar = ProgressBar.create(
        title: 'Getting completions',
        total: reader.total_rows,
        format: '%t: |%B| %c/%C'
      )
      error_counter = 0

      reader.read do |data_row|
        completion = duo_chat.completion(data_row)
        writer.write(completion)

        progressbar.increment
      rescue StandardError => error
        puts "Error: #{error}"

        sleep(2)
        error_counter += 1
        retry if error_counter < error_limit
      end

      writer.close
      progressbar.finish
    end
  end
end
