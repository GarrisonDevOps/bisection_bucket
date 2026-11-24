# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class DatasetReader
        DataRow = Struct.new(:ref, :query, :resource, keyword_init: true)

        attr_reader :total_rows

        def initialize(dataset_dir, meta_file_name = ".meta.json")
          raise ArgumentError, "Dataset directory not found: #{dataset_dir}" unless Dir.exist?(dataset_dir)

          @dataset_dir = dataset_dir
          meta = parse_meta_json(meta_file_name)
          @file_names = meta.fetch(:file_names, [])
          @total_rows = meta.fetch(:total_rows, 0)
        end

        def read
          file_names.each do |file_name|
            jsonl_file_path = File.join(dataset_dir, file_name)
            File.open(jsonl_file_path).each_line do |line|
              raw = ::Gitlab::Json.safe_parse(line.chomp, symbolize_names: true)

              resource = ::Gitlab::Duo::Chat::Request::Resource.new(**raw[:resource])
              data_row = DataRow.new(ref: raw[:ref], query: raw[:query], resource: resource)

              yield data_row
            end
          end
        end

        private

        attr_reader :dataset_dir, :file_names

        def parse_meta_json(meta_file_name)
          meta_file_path = File.join(dataset_dir, meta_file_name)
          raise ArgumentError, "Meta file not found: #{meta_file_path}" unless File.exist?(meta_file_path)

          ::Gitlab::Json.safe_parse(File.read(meta_file_path), symbolize_names: true)
        end
      end
    end
  end
end
