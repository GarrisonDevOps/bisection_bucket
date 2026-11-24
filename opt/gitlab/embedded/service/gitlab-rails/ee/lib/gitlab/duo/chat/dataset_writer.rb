# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class DatasetWriter
        def initialize(output_dir)
          @output_dir = output_dir
          FileUtils.mkdir_p(@output_dir)

          @current_file = create_new_file
        end

        def write(completion)
          current_file.puts(::Gitlab::Json.dump(completion))
        end

        def close
          current_file.close
        end

        private

        attr_reader :output_dir, :current_file

        def create_new_file
          file_path = File.join(@output_dir, "#{SecureRandom.hex}.jsonl")
          File.new(file_path, 'w')
        end
      end
    end
  end
end
