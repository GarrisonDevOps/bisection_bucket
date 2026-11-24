# frozen_string_literal: true

module RedisCloudAuth
  module Providers
    # Amazon ElastiCache IAM provider. Verified live against ElastiCache
    # Serverless (IAM auth + TLS).
    #
    # ElastiCache IAM authentication uses a short-lived "auth token" that is a
    # SigV4-presigned GET URL (service "elasticache") with Action=connect and
    # User=<user-id>, valid ~15 minutes. The token sent as the Redis password is
    # that presigned URL with the scheme stripped; the Redis AUTH username is the
    # ElastiCache user id.
    #
    # Descriptor keys:
    #   :user_id     ElastiCache IAM-enabled user (also the Redis AUTH username)
    #   :cache_name  replication group / cluster id (the presign host label)
    #   :region      AWS region
    #   :credentials optional object with #access_key_id/#secret_access_key/
    #                #session_token; defaults to the standard AWS env vars
    #
    # Implements the same interface as the Azure provider:
    #   #call => [username, token]   #expires_at => Time
    class ElastiCache
      TOKEN_TTL = 900 # seconds; ElastiCache IAM tokens are valid for 15 minutes.
      REFRESH_MARGIN = 60

      def self.build(descriptor)
        new(descriptor)
      end

      def initialize(descriptor)
        @user_id = descriptor.fetch(:user_id)
        @cache_name = descriptor.fetch(:cache_name)
        @region = descriptor.fetch(:region)
        @credentials = descriptor[:credentials]
        @mutex = Mutex.new
      end

      def call
        @mutex.synchronize do
          generate! if @token.nil? || @expires_at.nil? || (@expires_at - REFRESH_MARGIN) <= Time.now
          [@user_id, @token]
        end
      end

      def expires_at
        @mutex.synchronize { @expires_at }
      end

      private

      def generate!
        require "aws-sigv4"
        require "cgi"

        signer = Aws::Sigv4::Signer.new(
          service: "elasticache",
          region: @region,
          credentials: aws_credentials
        )

        url = signer.presign_url(
          http_method: "GET",
          url: "https://#{@cache_name}/?Action=connect&User=#{CGI.escape(@user_id)}",
          body: "",
          expires_in: TOKEN_TTL
        ).to_s

        @token = url.sub(%r{\Ahttps?://}, "")
        @expires_at = Time.now + TOKEN_TTL
      end

      def aws_credentials
        return @credentials if @credentials

        Aws::Sigv4::Credentials.new(
          access_key_id: ENV.fetch("AWS_ACCESS_KEY_ID"),
          secret_access_key: ENV.fetch("AWS_SECRET_ACCESS_KEY"),
          session_token: ENV.fetch("AWS_SESSION_TOKEN", nil)
        )
      end
    end
  end
end
