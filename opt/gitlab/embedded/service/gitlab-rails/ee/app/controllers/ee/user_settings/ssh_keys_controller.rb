# frozen_string_literal: true

module EE
  module UserSettings
    module SshKeysController
      extend ActiveSupport::Concern

      prepended do
        before_action :check_ssh_keys_enabled
      end

      private

      def check_ssh_keys_enabled
        render_404 if current_user.ssh_keys_disabled?
      end
    end
  end
end
