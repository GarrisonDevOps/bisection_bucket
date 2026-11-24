# frozen_string_literal: true

module Sbom
  module Exporters
    module WriteBlob
      def write_blob(blob)
        Tempfile.open('write_blob') do |file|
          file.write(blob)

          if block_given?
            yield file
          else
            file.rewind
            file.read
          end
        end
      end

      def write_json_blob(data, &block)
        blob = ::Gitlab::Json.dump(data)
        write_blob(blob, &block)
      end
    end
  end
end
