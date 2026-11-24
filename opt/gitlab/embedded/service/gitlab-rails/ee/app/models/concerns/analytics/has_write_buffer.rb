# frozen_string_literal: true

module Analytics
  module HasWriteBuffer
    extend ActiveSupport::Concern

    class_methods do
      def write_buffer
        @buffer ||= write_buffer_options[:class].new(buffer_key: name.underscore)
      end

      attr_writer :write_buffer_options

      def write_buffer_options
        default_write_buffer_options.merge(@write_buffer_options || {})
      end

      def default_write_buffer_options
        {
          class: Analytics::DatabaseWriteBuffer
        }
      end
    end
  end
end
