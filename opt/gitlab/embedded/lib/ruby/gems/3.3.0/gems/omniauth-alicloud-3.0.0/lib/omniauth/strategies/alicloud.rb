# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Alicloud < OmniAuth::Strategies::OAuth2
      option :name, 'alicloud'

      option :client_options, {
        site: 'https://oauth.aliyun.com/',
        authorize_url: 'https://signin.aliyun.com/oauth2/v1/auth',
        token_url: 'https://oauth.aliyun.com/v1/token'
      }

      uid do
        raw_info['sub']
      end

      info do
        {
          name: raw_info['name'],
          email: raw_info['login_name'] || raw_info['upn'],
          username: raw_info['name'],
          sub: raw_info['sub'],
          aid: raw_info['aid'],
          uid: raw_info['uid']
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def callback_url
        full_host + callback_path
      end

      protected

      def raw_info
        @raw_info ||= access_token.get('/v1/userinfo').parsed || {}
      end
    end
  end
end

OmniAuth.config.add_camelization 'alicloud', 'Alicloud'
