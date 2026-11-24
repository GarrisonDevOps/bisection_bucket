# frozen_string_literal: true

module EE
  module Wiki
    extend ActiveSupport::Concern
    prepended do
      include Elastic::WikiRepositoriesSearch
    end

    # No need to have a Kerberos Web url. Kerberos URL will be used only to
    # clone
    def kerberos_url_to_repo
      [::Gitlab.config.build_gitlab_kerberos_url, '/', full_path, '.git'].join('')
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      def base_class
        ::Wiki
      end

      override :use_separate_indices?
      def use_separate_indices?
        true
      end
    end
  end
end
