# frozen_string_literal: true

module Gitlab
  module Scim
    class ProvisioningResponse
      attr_reader :status, :message, :identity, :group_link

      def initialize(status:, message: nil, identity: nil, group_link: nil)
        @status = status
        @message = message
        @identity = identity
        @group_link = group_link
      end
    end
  end
end
