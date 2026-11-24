# frozen_string_literal: true

module EE
  module Search
    module PipeAbuseDetector
      extend ::Gitlab::Utils::Override

      private

      override :search_type_requires_pipe_detection?
      def search_type_requires_pipe_detection?
        return false if !::Gitlab::Utils.to_boolean(params[:regex]) && search_type == 'zoekt'

        super
      end
    end
  end
end
