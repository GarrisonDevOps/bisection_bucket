# frozen_string_literal: true

module Geo
  class PushUser
    include ::Gitlab::Identifier

    def initialize(gl_id)
      @gl_id = gl_id
    end

    def user
      @user ||=
        case gl_id
        when /\Akey-\d+\z/
          identify_using_ssh_key(gl_id)
        when /\Auser-\d+\z/
          identify_using_user(gl_id)
        when /\Ausername-[a-zA-Z0-9_\-.]+\z/
          identify_using_username(gl_id)
        end
    end

    def deploy_key
      @deploy_key ||= identify_using_deploy_key(gl_id)
    end

    private

    attr_reader :gl_id
  end
end
